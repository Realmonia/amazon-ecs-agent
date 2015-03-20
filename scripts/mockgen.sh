#!/bin/bash
# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the
# "License"). You may not use this file except in compliance
#  with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.
#
# This script wraps the mockgen tool and inserts licensing information.

package="$1"
inputfile="$2"
outputfile="$(echo ${inputfile} | sed -e 's/\.go$/_mock_test.go/')"

echo "Generating mocks from ${inputfile} to ${outputfile} in package ${package}"

export PATH="${GOPATH//://bin:}/bin:$PATH"

tmp_gen="$(mktemp)"
mockgen -source=$(pwd)/${inputfile} -package ${package} | goimports > "${tmp_gen}"
cat  > $(pwd)/${outputfile} << EOF
// Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// Source: $(basename ${inputfile}) in package ${package}
$(grep -v "// Source: .*${inputfile}" ${tmp_gen})
EOF
rm "${tmp_gen}"
