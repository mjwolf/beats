// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package types

//go:generate stringer -linecomment=true -type=Type,HookPoint,Field -output=gen_types_string.go

type Type uint64

const (
	ProcessFork Type = iota
	ProcessExec
	ProcessExit
	ProcessSetsid
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
