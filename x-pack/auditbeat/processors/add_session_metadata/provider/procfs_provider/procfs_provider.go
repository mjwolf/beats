// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package procfs_provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/procfs"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/provider"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/types"

	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	syscallField = "auditd.data.syscall"
)

type svc struct {
	ctx                context.Context
	logger             logp.Logger
	db                 processdb.DB
	reader procfs.Reader
	stop               chan (bool)
	ready, failedState bool
	pidField string
}

func NewProvider(ctx context.Context, logger logp.Logger, db processdb.DB, reader procfs.Reader, pidField string) (provider.Provider, error) {
	return &svc{
		ctx:    ctx,
		logger: logger,
		db:     db,
		reader: reader,
		pidField: pidField,
	}, nil
}

func (s *svc) Start() error {
	return nil
}

func (s *svc) Stop() error {
	return nil
}

// UpdateDB will update the process DB with process info from procfs or the event itself
func (s *svc) UpdateDB(ev *beat.Event) error {
	pi, err := ev.Fields.GetValue(s.pidField)
	if err != nil {
		return fmt.Errorf("event not supported, no pid")
	}
	pid, ok := pi.(int)
	if !ok {
		return fmt.Errorf("pid field not int")
	}

	syscall, err := ev.GetValue(syscallField)
	if err != nil {
		return fmt.Errorf("event not supported, no syscall data")
	}

	switch syscall {
	case "execveat":
		fallthrough
	case "execve":
		pe := types.ProcessExecEvent{}

		proc_info, err := s.reader.GetProcess(uint32(pid))
		if err == nil {
			pe.Pids = proc_info.Pids
			pe.Creds = proc_info.Creds
			pe.CTty = proc_info.CTty
			pe.Cwd = proc_info.Cwd
			pe.Argv = proc_info.Argv
			pe.Env = proc_info.Env
			pe.Filename = proc_info.Filename
			pe.PidsSsCgroupPath = proc_info.CGroupPath
		} else {
			s.logger.Errorf("get process info from proc for pid %v: %w", pid, err)
			// If proc scraping failed, gather as much info as possible from syscalls
			// and process data already in DB.
			pe.Pids.Tgid = uint32(pid)
			var intr interface{}
			var i int
			var ok bool
			var parent types.Process
			intr, err := ev.Fields.GetValue("process.parent.pid")
			if err != nil {
				goto out
			}
			if i, ok = intr.(int); !ok {
				goto out
			}
			pe.Pids.Ppid = uint32(i)

			parent, err = s.db.GetProcess(pe.Pids.Ppid)
			if err != nil {
				goto out
			}
			pe.Pids.Sid = parent.SessionLeader.PID

			intr, err = ev.Fields.GetValue("process.working_directory")
			if err != nil {
				goto out
			}
			pe.Cwd = intr.(string)
			out:
		}
		err = s.db.InsertExec(pe)
		if err != nil {
			return fmt.Errorf("insert exec to db: %w", err)
		}
	case "exit_group":
		pe := types.ProcessExitEvent{
			Pids: types.PidInfo{
				Tgid: uint32(pid),
			},
		}
		s.db.InsertExit(pe)
	case "setsid":
		s.logger.Debug("got setsid!")
		proc, err := s.db.GetProcess(uint32(pid))
		if err == nil {
			s.logger.Debug("found!")
		}
		s.logger.Debugf("Initial proc: %v", proc)

		intr, err := ev.Fields.GetValue("auditd.data.exit")
		if err != nil {
			return fmt.Errorf("syscall exit value not found")
		}
		ret, _ := strconv.Atoi(intr.(string))
		if err == nil && ret > 0 {
			setsid_ev := types.ProcessSetsidEvent {
				Pids: types.PidInfo {
					Tgid: uint32(pid),
					Sid: uint32(pid),
				},
			}
			s.db.InsertSetsid(setsid_ev)
		} else {
			s.logger.Debugf("setsid syscall failed!")
		}

		proc, _ = s.db.GetProcess(uint32(pid))
		s.logger.Debugf("Final proc: %v", proc)
	}

	return nil
}

func (s *svc) SetPidField (pidField string) {
	s.pidField = pidField
}
