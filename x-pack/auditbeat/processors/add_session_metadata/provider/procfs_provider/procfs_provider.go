// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package procfs_provider

import (
	"context"
	"fmt"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/procfs"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/provider"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/types"

	//	"github.com/elastic/beats/v7/auditbeat/processors/add_session_metadata/types"

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

func NewProvider(ctx context.Context, logger logp.Logger, db processdb.DB, pidField string) (provider.Provider, error) {
	reader := procfs.NewProcfsReader(logger)
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

func (s *svc) Update(ev *beat.Event) error {
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
		pe := types.ProcessExecEvent{
			Pids: types.PidInfo{},
			Creds: types.CredInfo{},
			CTty: types.TtyDev{},
		}

		proc_info, err := s.reader.GetProcess(pid)
		if err != nil {
			s.logger.Errorf("get process info from proc for pid %v: %w", pid, err)
			// Some infa can be taken from syscall data
			// PID and StartTime are required, others are optional
			pe.Pids.Tgid = uint32(pid)
			var intr interface{}
			var parent types.Process
			intr, err := ev.Fields.GetValue("process.parent.pid")
			if err != nil {
				goto out
			}
			pe.Pids.Ppid = uint32(intr.(int))

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
		} else {
			pe.Pids = proc_info.Pids
			pe.Creds = proc_info.Creds
			pe.CTty = proc_info.CTty
			pe.Cwd = proc_info.Cwd
			pe.Argv = proc_info.Argv
			pe.Env = proc_info.Env
			pe.Filename = proc_info.Filename
			pe.PidsSsCgroupPath = proc_info.CGroupPath
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
		intr, err := ev.Fields.GetValue(s.pidField)
		if err != nil {
			return fmt.Errorf("get pid for setsid event: %w", err)
		}
		pid, ok := intr.(int)
		if !ok {
			return fmt.Errorf("pid not int")
		}
		setsid_ev := types.ProcessSetsidEvent {
			Pids: types.PidInfo {
				Tgid: uint32(pid),
				Sid: uint32(pid),
			},
		}
		s.db.InsertSetsid(setsid_ev)
	}
	return nil
}

func (s *svc) SetPidField (pidField string) {
	s.pidField = pidField
}
