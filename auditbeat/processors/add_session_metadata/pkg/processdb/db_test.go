// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package processdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFilteredExecutable(t *testing.T) {
	assert.Equal(t, true, isFilteredExecutable("runc"))
	assert.Equal(t, true, isFilteredExecutable("containerd-shim-v2-abcd"))
	assert.Equal(t, true, isFilteredExecutable("containerd-shim"))
	assert.Equal(t, true, isFilteredExecutable("calico-node"))
	assert.Equal(t, true, isFilteredExecutable("check-status"))
	assert.Equal(t, true, isFilteredExecutable("conmon"))
	assert.Equal(t, false, isFilteredExecutable("bash"))
}

func TestGetTtyType(t *testing.T) {
	assert.Equal(t, TtyConsole, getTtyType(4, 0))
	assert.Equal(t, Pts, getTtyType(136, 0))
	assert.Equal(t, Tty, getTtyType(4, 64))
	assert.Equal(t, TtyUnknown, getTtyType(1000, 1000))
}

func TestIsContainerRuntime(t *testing.T) {
	assert.Equal(t, true, isContainerRuntime("containerd-shim-v2-abcd"))
	assert.Equal(t, true, isContainerRuntime("containerd-shim"))
	assert.Equal(t, true, isContainerRuntime("runc"))
	assert.Equal(t, true, isContainerRuntime("conmon"))
	assert.Equal(t, false, isContainerRuntime("ls"))
}
