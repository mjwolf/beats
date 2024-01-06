package procfs

import (
	"time"

	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/timeutils"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/types"
)

type MockReader struct {
	entries map[uint32]MockEntry
}

type MockEntry struct {
	Exe     string
	Environ map[string]string
	Stat    Stat
	Cwd     string
	CGroupPath string
}

func NewMockReader() *MockReader {
	return &MockReader{
		entries: make(map[uint32]MockEntry),
	}
}

func (mock *MockReader) GetBootTime() (time.Time, error) {
	return time.Time{}, nil
}

func (mock *MockReader) AddEntry(pid uint32, entry MockEntry) {
	mock.entries[pid] = entry
}

func (mock *MockReader) GetExe(pid uint32) (string, error) {
	return mock.entries[pid].Exe, nil
}

func (mock *MockReader) GetEnviron(pid uint32) (map[string]string, error) {
	return mock.entries[pid].Environ, nil
}

func (mock *MockReader) GetCwd(pid uint32) (string, error) {
	return mock.entries[pid].Cwd, nil
}

func (mock *MockReader) GetStat(pid uint32) (Stat, error) {
	return mock.entries[pid].Stat, nil
}

func (mock *MockReader) GetProcess(pid int) (*ProcessInfo, error) {
	pi := ProcessInfo{}
	return &pi, nil
}

// doesn't return anything right now
func (mock *MockReader) GetAllProcesses() ([]ProcessInfo, error) {
	ret := make([]ProcessInfo, 0)

	for pid, entry := range mock.entries {
		ret = append(ret, ProcessInfo{
			Pids: types.PidInfo{
				StartTimeNs: timeutils.TicksToNs(entry.Stat.Starttime),
				Tid:         pid,
				Tgid:        pid,
				Ppid:        uint32(entry.Stat.PPID),
				Pgid:        uint32(entry.Stat.PGRP),
				Sid:         uint32(entry.Stat.Session),
			},
			Cwd:      entry.Cwd,
			Env:      entry.Environ,
			Filename: entry.Exe,
			CGroupPath: entry.CGroupPath,
		})
	}

	return ret, nil
}
