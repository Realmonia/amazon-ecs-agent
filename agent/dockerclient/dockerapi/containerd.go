package dockerapi

import (
	"context"
	c "github.com/containerd/containerd"
)

type containerd struct {
	client *c.Client
}

func NewContainerd() (*containerd, error) {
	client, err := c.New("/run/containerd/containerd.sock")
	if err != nil {
		return nil, err
	}
	d := &containerd{
		client: client,
	}

	return d, nil
}

func (d *containerd) getContainerdTask(ctx context.Context,
	containerId string) (c.Container, c.Task, error) {
	container, err := d.client.LoadContainer(ctx, containerId)
	if err != nil {
		return nil, nil, err
	}

	// TODO: Find out if we should care
	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	return container, task, nil
}
