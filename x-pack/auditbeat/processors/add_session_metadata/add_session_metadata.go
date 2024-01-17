// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package add_session_metadata

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/elastic-agent-libs/monitoring"

	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/procfs"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/provider"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/provider/ebpf_provider"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	processorName = "add_session_metadata"
	logName       = "processor." + processorName
)

var reg *monitoring.Registry

func init() {
	processors.RegisterPlugin(processorName, New)
	reg = monitoring.Default.NewRegistry(logName, monitoring.DoNotReport)
}

type addSessionMetadata struct {
	config   Config
	logger   *logp.Logger
	db       processdb.DB
	provider provider.Provider
}

func New(cfg *config.C) (beat.Processor, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("fail to unpack the %v configuration: %w", processorName, err)
	}

	logger := logp.NewLogger(logName)

	ctx := context.TODO()
	reader := procfs.NewProcfsReader(*logger)
	db := processdb.NewSimpleDB(reader, *logger)

	backfilledPIDs := db.ScrapeProcfs()
	logger.Debugf("backfilled %d processes", len(backfilledPIDs))

	switch c.Backend {
	case "ebpf":
		p, err := ebpf_provider.NewProvider(ctx, *logger, db)
		if err != nil {
			return nil, fmt.Errorf("failed to create ebpf provider: %w", err)
		}
		return &addSessionMetadata{
			config:   c,
			logger:   logger,
			db:       db,
			provider: p,
		}, nil
	default:
		return nil, fmt.Errorf("unknown backend configuration")
	}
}

func (p *addSessionMetadata) Run(ev *beat.Event) (*beat.Event, error) {
	 _, err := ev.GetValue(p.config.PidField)
	 if err != nil {
		// Do not attempt to enrich events without PID; it's not a supported event
		return ev, nil
	}

	err = p.provider.UpdateDB(ev)
	if err != nil {
		return ev, err
	}

	result, err := p.enrich(ev)
	if err != nil {
		return ev, fmt.Errorf("enriching event: %w", err)
	}
	return result, nil
}

func (p *addSessionMetadata) String() string {
	return fmt.Sprintf("%v=[backend=%s, pid_field=%s, override_fields=%t]",
		processorName, p.config.Backend, p.config.PidField, p.config.ReplaceFields)
}

func (p *addSessionMetadata) enrich(ev *beat.Event) (*beat.Event, error) {
	pidIf, err := ev.GetValue(p.config.PidField)
	if err != nil {
		return nil, err
	}
	pid, err := pidToUInt32(pidIf)
	if err != nil {
		return nil, fmt.Errorf("cannot parse pid field '%s': %w", p.config.PidField, err)
	}

	fullProcess, err := p.db.GetProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("pid %v not found in db: %w", pid, err)
	}

	result := ev.Clone()

	processMap := fullProcess.ToMap()

	mapstr.MergeFieldsDeep(result.Fields["process"].(mapstr.M), processMap, true)

	if p.config.ReplaceFields {
		if err := p.replaceFields(result); err != nil {
			return nil, fmt.Errorf("replace fields: %w", err)
		}
	}
	return result, nil
}

//pidToUInt32 converts PID value to uint32
func pidToUInt32(value interface{}) (pid uint32, err error) {
	switch v := value.(type) {
	case string:
		nr, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("error converting string to integer: %w", err)
		}
		pid = uint32(nr)
	case uint32:
		pid = v
	case int, int8, int16, int32, int64:
		pid64 := reflect.ValueOf(v).Int()
		if pid = uint32(pid64); int64(pid) != pid64 {
			return 0, fmt.Errorf("integer out of range: %d", pid64)
		}
	case uint, uintptr, uint8, uint16, uint64:
		pidu64 := reflect.ValueOf(v).Uint()
		if pid = uint32(pidu64); uint64(pid) != pidu64 {
			return 0, fmt.Errorf("integer out of range: %d", pidu64)
		}
	default:
		return 0, fmt.Errorf("not an integer or string, but %T", v)
	}
	return pid, nil
}

// replaceFields replaces event fields with values suitable user with the session viewer in Kibana
// The current version of session view in Kibana expects different values than what are used by auditbeat
// for some fields. This function converts these field to have values that will work with session view.
//
// This function is temporary, and can be removed when Kibana is updated to work with the auditbeat field values.
func (p *addSessionMetadata) replaceFields(ev *beat.Event) error {
	kind, err := ev.Fields.GetValue("event.kind")
	if err != nil {
		return err
	}
	isAuditdEvent, err := ev.Fields.HasKey("auditd")
	if err != nil {
		return err
	}
	if kind == "event" && isAuditdEvent {
		// process start
		syscall, err := ev.Fields.GetValue("auditd.data.syscall")
		if err != nil {
			return err
		}
		switch syscall {
		case "execveat":
			fallthrough
		case "execve":
			ev.Fields.Put("event.action", []string{"exec", "fork"})
			ev.Fields.Put("event.type", []string{"start"})

		case "exit_group":
			ev.Fields.Put("event.action", []string{"end"})
			ev.Fields.Put("event.type", []string{"end"})
			ev.Fields.Put("process.end", time.Now())
		}
	}
	return nil
}