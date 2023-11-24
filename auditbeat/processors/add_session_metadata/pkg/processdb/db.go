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
	"strings"

	"github.com/elastic/beats/v7/auditbeat/processors/add_session_metadata/types"
)

type DB interface {
	InsertFork(fork types.ProcessForkEvent) error
	InsertExec(exec types.ProcessExecEvent) error
	InsertSetsid(setsid types.ProcessSetsidEvent) error
	InsertExit(exit types.ProcessExitEvent) error
	GetProcess(pid uint32) (types.Process, error)
	GetEntryType(pid uint32) (EntryType, error)
	GetCgroupPath(pid uint32) (string, error)
	ScrapeProcfs() []uint32
}

type TtyType int

const (
	TtyUnknown TtyType = iota
	Pts
	Tty
	TtyConsole
)

type EntryType string

const (
	Init         EntryType = "init"
	Sshd         EntryType = "sshd"
	Ssm          EntryType = "ssm"
	Container    EntryType = "container"
	Terminal     EntryType = "terminal"
	EntryConsole EntryType = "console"
	EntryUnknown EntryType = "unknown"
)

var containerRuntimes = [...]string{
	"containerd-shim",
	"runc",
	"conmon",
}

// "filtered" executables are executables that relate to internal
// implementation details of entry mechanisms. The set of circumstances under
// which they can become an entry leader are reduced compared to other binaries
// (see implementation and unit tests).
var filteredExecutables = [...]string{
	"runc",
	"containerd-shim",
	"calico-node",
	"check-status",
	"conmon",
}

const (
	ptsMinMajor     = 136
	ptsMaxMajor     = 143
	ttyMajor        = 4
	consoleMaxMinor = 63
	ttyMaxMinor     = 255
)

func stringStartsWithEntryInList(str string, list []string) bool {
	for _, entry := range list {
		if strings.HasPrefix(str, entry) {
			return true
		}
	}

	return false
}

func isContainerRuntime(executable string) bool {
	return stringStartsWithEntryInList(executable, containerRuntimes[:])
}

func isFilteredExecutable(executable string) bool {
	return stringStartsWithEntryInList(executable, filteredExecutables[:])
}

func getTtyType(major uint16, minor uint16) TtyType {
	if major >= ptsMinMajor && major <= ptsMaxMajor {
		return Pts
	}

	if ttyMajor == major {
		if minor <= consoleMaxMinor {
			return TtyConsole
		} else if minor > consoleMaxMinor && minor <= ttyMaxMinor {
			return Tty
		}
	}

	return TtyUnknown
}
