package dockerapi

import (
	"bufio"
	"context"
	log "github.com/cihub/seelog"
	cgroups "github.com/containerd/cgroups/stats/v1"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl"
	"github.com/docker/docker/api/types"
	dockerstats "github.com/docker/docker/api/types"
	"github.com/pkg/errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// containerStats encapsulates cgroup and network stats.
type containerStats struct {
	CgroupStats  *cgroupStats
	NetworkStats *networkStats
	Timestamp    time.Time
}

// cgroupStats encapsulates the raw CPU and memory utilization, and Block IO read and write bytes from cgroup fs.
type cgroupStats struct {
	CPUUsageUserHZ   uint64
	MemoryUsageBytes uint64
	DiskReadBytes    uint64
	DiskWriteBytes   uint64
}

type networkStats struct {
	RxBytes       uint64
	RxDropped     uint64
	RxErrors      uint64
	RxPackets     uint64
	TxBytes       uint64
	TxDropped     uint64
	TxErrors      uint64
	TxPackets     uint64
	RxBytesPerSec float64
	TxBytesPerSec float64
}

type NetworkRateStats struct {
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
}

// StatusJSON is meant to be a wrapper over docker stats data type
// with network rate stats included.
type DockerStatsJSON struct {
	types.StatsJSON

	NetworkRate *NetworkRateStats `json:"network_rate_stats,omitempty"`
}

const (
	opRead               = "Read"
	opWrite              = "Write"
	nanoSecondsPerSecond = 1e9
	// cpuStatsBufferSize is the buffer to read in each line in /proc/stat
	// 128 bytes should be sufficient to hold all fields in one line
	// /proc/stat fields are listed in linux man page: https://man7.org/linux/man-pages/man5/proc.5.html
	cpuStatsBufferSize = 128
	// clockTicksPerSecond represents the unix constant _SC_CLK_TCK, which is 100 in linux systems. This is replacing
	// a call to system.GetClockTicks() in the opencontainers library. See https://github.com/containerd/cgroups/pull/12.
	clockTicksPerSecond = uint64(100)
)

// dockerStatsToContainerStats converts cgroup metrics and network stats to container stats.
func dockerStatsToContainerStats(sample *DockerStatsJSON) *containerStats {
	cpuUsage := sample.CPUStats.CPUUsage.TotalUsage / uint64(runtime.NumCPU())
	memoryUsage := sample.MemoryStats.Usage - sample.MemoryStats.Stats["cache"]
	diskReadBytes, diskWriteBytes := getDiskStats(sample)
	cgroupStats := &cgroupStats{
		CPUUsageUserHZ:   cpuUsage,
		MemoryUsageBytes: memoryUsage,
		DiskReadBytes:    diskReadBytes,
		DiskWriteBytes:   diskWriteBytes,
	}
	networkStats := getNetworkStats(sample)

	return &containerStats{
		CgroupStats:  cgroupStats,
		NetworkStats: networkStats,
		Timestamp:    sample.Read,
	}
}

func getDiskStats(sample *DockerStatsJSON) (uint64, uint64) {
	if sample.BlkioStats.IoServiceBytesRecursive == nil {
		return uint64(0), uint64(0)
	}
	var diskReadBytes, diskWriteBytes uint64 = 0, 0
	for _, blockStat := range sample.BlkioStats.IoServiceBytesRecursive {
		switch op := blockStat.Op; op {
		case opRead:
			diskReadBytes += blockStat.Value
		case opWrite:
			diskWriteBytes += blockStat.Value
		default:
			continue
		}
	}

	return diskReadBytes, diskWriteBytes
}

func getNetworkStats(sample *DockerStatsJSON) *networkStats {
	var networkStats = &networkStats{}

	if sample.Networks != nil {
		for _, netLink := range sample.Networks {
			networkStats.RxBytes += netLink.RxBytes
			networkStats.RxPackets += netLink.RxPackets
			networkStats.RxErrors += netLink.RxErrors
			networkStats.RxDropped += netLink.RxDropped

			networkStats.TxBytes += netLink.TxBytes
			networkStats.TxPackets += netLink.TxPackets
			networkStats.TxErrors += netLink.TxErrors
			networkStats.TxDropped += netLink.TxDropped
		}
	}

	if sample.NetworkRate != nil {
		networkStats.RxBytesPerSec = sample.NetworkRate.RxBytesPerSec
		networkStats.TxBytesPerSec = sample.NetworkRate.TxBytesPerSec
	}

	return networkStats
}

// cgroupStatsToDockerStats transforms cgroup metrics format to docker defined statsJSON format.
// Adopted from https://github.com/moby/moby/blob/e4611b3e074c48e90ea2ea2fc138ede2ce87fb36/daemon/daemon_unix.go#L1372
func (d *containerd) cgroupStatsToDockerStats(
	containerName string,
	taskARN string,
	cgroupStats *cgroups.Metrics,
	onlineCPU uint32,
	previousContainerStats *DockerStatsJSON,
) *DockerStatsJSON {
	s := &DockerStatsJSON{}
	s = d.cgToDockerCPUStats(containerName, taskARN, cgroupStats, onlineCPU, previousContainerStats, s)
	s = d.cgToDockerMemStats(cgroupStats, s)
	s = d.cgToDockerBlkioStats(cgroupStats, s)

	return s
}

// cgToDockerCPUStats transforms cgroup CPU metrics to docker defined format.
func (d *containerd) cgToDockerCPUStats(
	containerName string,
	taskARN string,
	cgroupStats *cgroups.Metrics,
	onlineCPU uint32,
	previousContainerStats *DockerStatsJSON,
	dockerStats *DockerStatsJSON,
) *DockerStatsJSON {
	dockerStats.CPUStats = dockerstats.CPUStats{}
	// Update the systemCPUUsage and onlineCPU. They are not from the cgroup stats.
	// Instead, read them from system calls and "/proc/stats."
	systemCPUUsage, err := GetSystemCPUUsage()
	if err != nil {
		log.Warn("Skip updating system cpu usage with err: %v", err)
	} else {
		dockerStats.CPUStats.SystemUsage = systemCPUUsage
	}

	dockerStats.CPUStats.OnlineCPUs = onlineCPU

	// The logic is mostly mirroring Docker's behavior. Reference:
	// https://github.com/moby/moby/blob/e4611b3e074c48e90ea2ea2fc138ede2ce87fb36/daemon/daemon_unix.go#L1398
	if cgroupStats.CPU != nil {
		if cgroupStats.CPU.Usage != nil {
			dockerStats.CPUStats.CPUUsage = dockerstats.CPUUsage{
				TotalUsage:        cgroupStats.CPU.Usage.Total,
				PercpuUsage:       cgroupStats.CPU.Usage.PerCPU,
				UsageInKernelmode: cgroupStats.CPU.Usage.Kernel,
				UsageInUsermode:   cgroupStats.CPU.Usage.User,
			}
		} else {
			log.Warn("Skip updating nil cpu usage")
		}

		// For warmpool instances, the cpuacct.usage_percpu file (cgroup file from where the percpu usages are read)
		// has random number of 0's. For the firecracker platform, the microVM does not have these extra 0's
		// in the usage file, making the percpu_usage array have elements equal to the #onlineCPUs.
		// To make output consistent, correct the length of percpuUsage array from an array with random number of 0's
		// to an array with elements = number of onlineCPUs (i.e. default 2).
		if len(dockerStats.CPUStats.CPUUsage.PercpuUsage) > int(onlineCPU) {
			dockerStats.CPUStats.CPUUsage.PercpuUsage = dockerStats.CPUStats.CPUUsage.PercpuUsage[0:int(onlineCPU)]
		}

		if previousContainerStats != nil {
			dockerStats.PreCPUStats = previousContainerStats.CPUStats
		} else {
			log.Debug("No previous stats. precpu_stats are zero")
		}

		if cgroupStats.CPU.Throttling != nil {
			dockerStats.CPUStats.ThrottlingData = dockerstats.ThrottlingData{
				Periods:          cgroupStats.CPU.Throttling.Periods,
				ThrottledPeriods: cgroupStats.CPU.Throttling.ThrottledPeriods,
				ThrottledTime:    cgroupStats.CPU.Throttling.ThrottledTime,
			}
		} else {
			log.Warn("Skip updating nil cpu throttling data")
		}
	}
	return dockerStats
}

// cgToDockerMemStats transforms cgroup memory metrics to docker defined format. The logic is
// mostly mirroring Docker's behavior. Reference:
// https://github.com/moby/moby/blob/e4611b3e074c48e90ea2ea2fc138ede2ce87fb36/daemon/daemon_unix.go#L1414
func (d *containerd) cgToDockerMemStats(
	cgroupStats *cgroups.Metrics,
	dockerStats *DockerStatsJSON,
) *DockerStatsJSON {
	dockerStats.MemoryStats = dockerstats.MemoryStats{}
	if cgroupStats.Memory != nil {
		raw := make(map[string]uint64)
		raw["cache"] = cgroupStats.Memory.Cache
		raw["rss"] = cgroupStats.Memory.RSS
		raw["rss_huge"] = cgroupStats.Memory.RSSHuge
		raw["mapped_file"] = cgroupStats.Memory.MappedFile
		raw["dirty"] = cgroupStats.Memory.Dirty
		raw["writeback"] = cgroupStats.Memory.Writeback
		raw["pgpgin"] = cgroupStats.Memory.PgPgIn
		raw["pgpgout"] = cgroupStats.Memory.PgPgOut
		raw["pgfault"] = cgroupStats.Memory.PgFault
		raw["pgmajfault"] = cgroupStats.Memory.PgMajFault
		raw["inactive_anon"] = cgroupStats.Memory.InactiveAnon
		raw["active_anon"] = cgroupStats.Memory.ActiveAnon
		raw["inactive_file"] = cgroupStats.Memory.InactiveFile
		raw["active_file"] = cgroupStats.Memory.ActiveFile
		raw["unevictable"] = cgroupStats.Memory.Unevictable
		raw["hierarchical_memory_limit"] = cgroupStats.Memory.HierarchicalMemoryLimit
		raw["hierarchical_memsw_limit"] = cgroupStats.Memory.HierarchicalSwapLimit
		raw["total_cache"] = cgroupStats.Memory.TotalCache
		raw["total_rss"] = cgroupStats.Memory.TotalRSS
		raw["total_rss_huge"] = cgroupStats.Memory.TotalRSSHuge
		raw["total_mapped_file"] = cgroupStats.Memory.TotalMappedFile
		raw["total_dirty"] = cgroupStats.Memory.TotalDirty
		raw["total_writeback"] = cgroupStats.Memory.TotalWriteback
		raw["total_pgpgin"] = cgroupStats.Memory.TotalPgPgIn
		raw["total_pgpgout"] = cgroupStats.Memory.TotalPgPgOut
		raw["total_pgfault"] = cgroupStats.Memory.TotalPgFault
		raw["total_pgmajfault"] = cgroupStats.Memory.TotalPgMajFault
		raw["total_inactive_anon"] = cgroupStats.Memory.TotalInactiveAnon
		raw["total_active_anon"] = cgroupStats.Memory.TotalActiveAnon
		raw["total_inactive_file"] = cgroupStats.Memory.TotalInactiveFile
		raw["total_active_file"] = cgroupStats.Memory.TotalActiveFile
		raw["total_unevictable"] = cgroupStats.Memory.TotalUnevictable

		if cgroupStats.Memory.Usage != nil {
			dockerStats.MemoryStats = dockerstats.MemoryStats{
				Stats:    raw,
				Usage:    cgroupStats.Memory.Usage.Usage,
				MaxUsage: cgroupStats.Memory.Usage.Max,
				Limit:    cgroupStats.Memory.Usage.Limit,
				Failcnt:  cgroupStats.Memory.Usage.Failcnt,
			}
		} else {
			dockerStats.MemoryStats = dockerstats.MemoryStats{
				Stats: raw,
			}
		}
	}

	return dockerStats
}

// cgToDockerBlkioStats transforms cgroup blkio metrics to docker defined format. The logic is
// mostly mirroring Docker's behavior. Reference:
// https://github.com/moby/moby/blob/e4611b3e074c48e90ea2ea2fc138ede2ce87fb36/daemon/daemon_unix.go#L1386
func (d *containerd) cgToDockerBlkioStats(
	cgroupStats *cgroups.Metrics,
	dockerStats *DockerStatsJSON,
) *DockerStatsJSON {
	dockerStats.BlkioStats = dockerstats.BlkioStats{}
	if cgroupStats.Blkio != nil {
		dockerStats.BlkioStats = dockerstats.BlkioStats{
			IoServiceBytesRecursive: copyBlkioEntry(cgroupStats.Blkio.IoServiceBytesRecursive),
			IoServicedRecursive:     copyBlkioEntry(cgroupStats.Blkio.IoServicedRecursive),
			IoQueuedRecursive:       copyBlkioEntry(cgroupStats.Blkio.IoQueuedRecursive),
			IoServiceTimeRecursive:  copyBlkioEntry(cgroupStats.Blkio.IoServiceTimeRecursive),
			IoWaitTimeRecursive:     copyBlkioEntry(cgroupStats.Blkio.IoWaitTimeRecursive),
			IoMergedRecursive:       copyBlkioEntry(cgroupStats.Blkio.IoMergedRecursive),
			IoTimeRecursive:         copyBlkioEntry(cgroupStats.Blkio.IoTimeRecursive),
			SectorsRecursive:        copyBlkioEntry(cgroupStats.Blkio.SectorsRecursive),
		}
	}

	return dockerStats
}

// copyBlkioEntry copies all blkio entries cgroup metrics format to docker defined format.
func copyBlkioEntry(entries []*cgroups.BlkIOEntry) []dockerstats.BlkioStatEntry {
	out := make([]dockerstats.BlkioStatEntry, len(entries))
	for i, re := range entries {
		out[i] = dockerstats.BlkioStatEntry{
			Major: re.Major,
			Minor: re.Minor,
			Op:    re.Op,
			Value: re.Value,
		}
	}
	return out
}

func (d *containerd) Metrics(ctx context.Context,
	containerId, containerName, taskArn string,
	onlineCPU uint32,
	previousContainerStats *DockerStatsJSON,
) (*DockerStatsJSON, error) {
	ctx = namespaces.WithNamespace(ctx, "moby")
	_, task, err := d.getContainerdTask(ctx, containerId)
	if err != nil {
		return nil, err
	}
	metric, err := task.Metrics(ctx)
	if err != nil {
		return nil, err
	}

	anydata, err := typeurl.UnmarshalAny(metric.Data)
	if err != nil {
		return nil, err
	}
	data, ok := anydata.(*cgroups.Metrics)
	if !ok {
		return nil, errors.New("cannot parse container metric data")
	}

	s := d.cgroupStatsToDockerStats(containerName, taskArn, data, onlineCPU, previousContainerStats)
	return s, nil
}

func GetSystemCPUUsage() (uint64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, errors.Wrap(err, "failed to open file /proc/stat")
	}
	bufReader := bufio.NewReaderSize(f, cpuStatsBufferSize)

	defer func() {
		f.Close()
	}()

	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			break
		}
		parts := strings.Fields(line)
		if parts[0] == "cpu" {
			if len(parts) < 8 {
				return 0, errors.New("invalid number of cpu fields")
			}
			var totalClockTicks uint64
			for _, i := range parts[1:8] {
				v, err := strconv.ParseUint(i, 10, 64)
				if err != nil {
					return 0, errors.Wrapf(err, "unable to convert value %s to int", i)
				}
				totalClockTicks += v
			}
			return (totalClockTicks * nanoSecondsPerSecond) / clockTicksPerSecond, nil
		}
	}
	return 0, errors.Wrap(err, "invalid stat format. Error trying to parse the '/proc/stat' file")
}
