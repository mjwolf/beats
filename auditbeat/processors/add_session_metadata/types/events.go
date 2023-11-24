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

package types

//go:generate stringer -linecomment=true -type=Type,HookPoint,Field -output=gen_types_string.go

type Type uint64

const (
	ProcessFork Type = iota
	ProcessExec
	ProcessExit
	ProcessSetsid
	FileCreateExecutable
	FileModifyExecutable
	FileCreateFile
	FileModifyFile
	FileDeleteFile
)

type HookPoint uint64

// IMPORTANT: Ensure that any new values added here have line comments with the
// string the hook point should translate to when it's placed in
// cloud_defend.hook_point
const (
	TracepointSchedProcessFork      HookPoint = iota // tracepoint__sched_process_fork
	TracepointSchedProcessExec                       // tracepoint__sched_process_exec
	TracepointSyscallsSysExitSetsid                  // tracepoint__syscalls_sys_exit_setsid
	KprobeTaskstatsExit                              // kprobe__taskstats_exit
	LsmPathChmod                                     // lsm__path_chmod
	LsmPathMknod                                     // lsm__path_mknod
	LsmFileOpen                                      // lsm__file_open
	LsmPathTruncate                                  // lsm__path_truncate
	LsmPathRename                                    // lsm__path_rename
	LsmPathLink                                      // lsm__path_link
	LsmPathUnlink                                    // lsm__path_unlink
	LsmTaskAlloc                                     // lsm__task_alloc
	LsmBprmCheckSecurity                             // lsm__bprm_check_security
)

type (
	Field     uint32
	VarlenMap map[Field]any
)

const (
	Cwd Field = iota + 1
	Argv
	Env
	Filename
	PidsSsCgroupPath
)

type PidInfo struct {
	StartTimeNs uint64 `json:"-"`
	Tid         uint32 `json:"-"`
	Tgid        uint32 `json:"tgid"`
	Vpid        uint32 `json:"-"`
	Ppid        uint32 `json:"-"`
	Pgid        uint32 `json:"-"`
	Sid         uint32 `json:"-"`
}

type CredInfo struct {
	Ruid         uint32 `json:"-"`
	Rgid         uint32 `json:"-"`
	Euid         uint32 `json:"-"`
	Egid         uint32 `json:"-"`
	Suid         uint32 `json:"-"`
	Sgid         uint32 `json:"-"`
	CapPermitted uint64 `json:"cap_permitted,string"`
	CapEffective uint64 `json:"cap_effective,string"`
}

type TtyWinsize struct {
	Rows uint16 `json:"-"`
	Cols uint16 `json:"-"`
}

type TtyTermios struct {
	CIflag uint32 `json:"-"`
	COflag uint32 `json:"-"`
	CLflag uint32 `json:"-"`
	CCflag uint32 `json:"-"`
}

type TtyDev struct {
	Minor   uint16     `json:"-"`
	Major   uint16     `json:"-"`
	Winsize TtyWinsize `json:"-"`
	Termios TtyTermios `json:"-"`
}

type Event struct {
	Meta Meta `json:"meta"`
	Body any  `json:"body"`
}

type Meta struct {
	Type        Type      `json:"type"`
	TimestampNs uint64    `json:"-"`
	HookPoint   HookPoint `json:"hook_point"`
	SelMatched  uint64    `json:"-"`

	// Actions to be (or that have been in the case of block) taken
	Log   bool `json:"log"`
	Alert bool `json:"alert"`
	Block bool `json:"block"`
}

type ProcessForkEvent struct {
	ParentPids PidInfo  `json:"parent_pids"`
	ChildPids  PidInfo  `json:"child_pids"`
	Creds      CredInfo `json:"creds"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
}

type ProcessExecEvent struct {
	Pids  PidInfo  `json:"pids"`
	Creds CredInfo `json:"creds"`
	CTty  TtyDev   `json:"-"`

	// varlen fields
	Cwd              string            `json:"cwd"`
	Argv             []string          `json:"-"`
	Env              map[string]string `json:"-"`
	Filename         string            `json:"filename"`
	PidsSsCgroupPath string            `json:"-"`
}

type ProcessExitEvent struct {
	Pids     PidInfo `json:"pids"`
	ExitCode int32   `json:"exit_code"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
}

type ProcessSetsidEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
}

type FileCreateExecutableEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
	Filename         string `json:"filename"`
}

type FileModifyExecutableEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
	Filename         string `json:"filename"`
}

type FileCreateFileEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
	Filename         string `json:"filename"`
}

type FileModifyFileEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
	Filename         string `json:"filename"`
}

type FileDeleteFileEvent struct {
	Pids PidInfo `json:"pids"`

	// varlen fields
	PidsSsCgroupPath string `json:"-"`
	Filename         string `json:"filename"`
}
