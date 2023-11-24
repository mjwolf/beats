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

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/assert"

	"golang.org/x/sys/unix"
)

var logger = logp.NewLogger("processdb")

// glue function to fit the return type required by these tests
func newSimpleDBIntf() DB {
	ret := NewSimpleDB(logger)
	return ret
}

func TestSimpleSingleProcessSessionLeaderEntryTypeTerminal(t *testing.T) {
	testSingleProcessSessionLeaderEntryTypeTerminal(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderLoginProcess(t *testing.T) {
	testSingleProcessSessionLeaderLoginProcess(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderChildOfInit(t *testing.T) {
	testSingleProcessSessionLeaderChildOfInit(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderChildOfSsmSessionWorker(t *testing.T) {
	testSingleProcessSessionLeaderChildOfSsmSessionWorker(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderChildOfSshd(t *testing.T) {
	testSingleProcessSessionLeaderChildOfSshd(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderChildOfContainerdShim(t *testing.T) {
	testSingleProcessSessionLeaderChildOfContainerdShim(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessSessionLeaderOfRunc(t *testing.T) {
	testSingleProcessSessionLeaderChildOfRunc(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessEmptyProcess(t *testing.T) {
	testSingleProcessEmptyProcess(newSimpleDBIntf)(t)
}

func TestSimpleSingleProcessOverwriteOldEntryLeader(t *testing.T) {
	testSingleProcessOverwriteOldEntryLeader(newSimpleDBIntf)(t)
}

func TestSimpleInitSshdBashLs(t *testing.T) {
	testInitSshdBashLs(newSimpleDBIntf)(t)
}

func TestSimpleInitSshdSshdBashLs(t *testing.T) {
	testInitSshdSshdBashLs(newSimpleDBIntf)(t)
}

func TestSimpleInitSshdSshdSshdBashLs(t *testing.T) {
	testInitSshdSshdSshdBashLs(newSimpleDBIntf)(t)
}

func TestSimpleInitContainerdContainerdShim(t *testing.T) {
	testInitContainerdContainerdShim(newSimpleDBIntf)(t)
}

func TestSimpleInitContainerdShimBashContainerdShimIsReparentedToInit(t *testing.T) {
	testInitContainerdShimBashContainerdShimIsReparentedToInit(newSimpleDBIntf)(t)
}

func TestSimpleInitContainerdShimPauseContainerdShimIsReparentedToInit(t *testing.T) {
	testInitContainerdShimPauseContainerdShimIsReparentedToInit(newSimpleDBIntf)(t)
}

func TestSimpleInitSshdBashLsAndGrepGrepOnlyHasGroupLeader(t *testing.T) {
	testInitSshdBashLsAndGrepGrepOnlyHasGroupLeader(newSimpleDBIntf)(t)
}

func TestSimpleInitSshdBashLsAndGrepGrepOnlyHasSessionLeader(t *testing.T) {
	testInitSshdBashLsAndGrepGrepOnlyHasSessionLeader(newSimpleDBIntf)(t)
}

func TestSimpleGrepInIsolation(t *testing.T) {
	testGrepInIsolation(newSimpleDBIntf)(t)
}

func TestSimpleKernelThreads(t *testing.T) {
	testKernelThreads(newSimpleDBIntf)(t)
}

func TestCapsFromU64ToECS(t *testing.T) {
	expected := []string{"CAP_CHOWN"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<unix.CAP_CHOWN)))

	expected = []string{"CAP_SYS_ADMIN"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<unix.CAP_SYS_ADMIN)))

	expected = []string{"CAP_BPF"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<39)))

	expected = []string{"CAP_CHECKPOINT_RESTORE"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<40)))

	expected = []string{"41"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<41)))

	expected = []string{"63"}
	assert.Equal(t, expected, ecsCapsFromU64(uint64(1<<63)))

	expected = []string{"CAP_CHOWN", "CAP_SYS_ADMIN", "CAP_BPF", "CAP_CHECKPOINT_RESTORE", "41", "63"}
	caps := uint64(1 << unix.CAP_CHOWN)
	caps |= uint64(1 << unix.CAP_SYS_ADMIN)
	caps |= uint64(1 << unix.CAP_BPF)
	caps |= uint64(1 << unix.CAP_CHECKPOINT_RESTORE)
	caps |= uint64(1 << 41)
	caps |= uint64(1 << 63)
	assert.Equal(t, expected, ecsCapsFromU64(caps))
}
