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

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/provider"
	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target $BPF_TARGET bpf ./probes/amalgam.c -- -I./probes/headers -I./probes/$BPF_TARGET

type svc struct {
	sync.Mutex
	ctx                context.Context
	logger             logp.Logger
	bpfObjects         bpfObjects
	rbReader           *ringbuf.Reader
	links              []link.Link
	eventChannels      sync.Map
	ready, failedState bool
}

func NewProvider(ctx context.Context, logger logp.Logger) (provider.Provider, error) {
	return &svc{
		ctx:    ctx,
		logger: logger,
		links:  make([]link.Link, 0),
	}, nil
}

func (s *svc) Started() bool {
	return s.ready || s.failedState
}

func (s *svc) CreateEventChannel(bufferSize uint32) <-chan types.Event {
	ch := make(chan types.Event, bufferSize)
	s.eventChannels.Store((chan<- types.Event)(ch), nil)
	return ch
}

func (s *svc) loadBpfProgs() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit remove memlock: %v", err)
	}

	// Resize the event_buffer_map. See modules/sensor/probes/varlen.h for the
	// full context, but TLDR this lets us get around percpu array size limits.
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("load BPF collection spec: %v", err)
	}
	spec.Maps["event_buffer_map"].MaxEntries = uint32(runtime.NumCPU())

	opts := ebpf.CollectionOptions{}

	if err := spec.LoadAndAssign(&s.bpfObjects, &opts); err != nil {
		return fmt.Errorf("error loading eBPF probes: %v", err)
	}

	// cilium/ebpf caches all the BTF information it reads from
	// /sys/kernel/btf/vmlinux it needs to load the programs. We however don't
	// need it after this function exits and it's large (~40MB). Remove all
	// references to it and force a GC (which might come far in the future if
	// we're under light memory pressure) for large memory savings.
	defer func() {
		btf.FlushKernelSpec()
		runtime.GC()
	}()

	programs := map[*ebpf.Program][]string{
		// Raw tracepoints
		s.bpfObjects.RawTpSchedProcessExec: {},
		s.bpfObjects.RawTpSchedProcessFork: {},

		// Tracepoints
		s.bpfObjects.TracepointSyscallsSysExitSetsid: {"syscalls", "sys_exit_setsid"},

		// Kprobes
		s.bpfObjects.KprobeTaskstatsExit: {spec.Programs["kprobe__taskstats_exit"].AttachTo},
	}

	for program, strs := range programs {
		var l link.Link
		switch program.Type() {
		case ebpf.TracePoint:
			if l, err = link.Tracepoint(strs[0], strs[1], program, nil); err != nil {
				return fmt.Errorf("load tracepoint program: %v", err)
			}
		case ebpf.Tracing:
			if l, err = link.AttachTracing(link.TracingOptions{
				Program: program,
			}); err != nil {
				return fmt.Errorf("load tracing program: %v", err)
			}
		case ebpf.Kprobe:
			if l, err = link.Kprobe(strs[0], program, nil); err != nil {
				return fmt.Errorf("load kprobe program: %v", err)
			}
		default:
			return fmt.Errorf("unhandled bpf program type for loading: %d", program.Type())
		}

		s.links = append(s.links, l)
	}

	var sp bpfSpecs
	if err := spec.Assign(&sp); err != nil {
		return fmt.Errorf("assign BPF specs: %v", err)
	}

	return nil
}

func (s *svc) initRingbuf() error {
	rd, err := ringbuf.NewReader(s.bpfObjects.bpfMaps.Ringbuf)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %v", err)
	}
	s.rbReader = rd
	return nil
}

func (s *svc) Start() error {
	s.logger.Infof("starting sensor service")

	if err := s.loadBpfProgs(); err != nil {
		s.failedState = true
		msg := "load bpf progs (please ensure required Linux capabilities are set. BPF, PERFMON, and SYS_RESOURCE are mandatory)"
		s.logger.Errorf("%s: %v", msg, err)
		return fmt.Errorf("%s: %v", msg, err)
	}

	if err := s.initRingbuf(); err != nil {
		s.failedState = true
		s.logger.Errorf("init ringbuf: %v", err)
		return err
	}

	// WARNING: This log cannot be changed as the MKT relies upon it to detect
	// when the probes have been loaded
	s.logger.Info("probes initialized")

	s.ready = true

	return s.eventLoop()
}

func (s *svc) Stop() error {
	for _, l := range s.links {
		l.Close()
	}

	s.bpfObjects.Close()

	s.eventChannels.Range(func(k, v any) bool {
		ch, ok := k.(chan<- types.Event)
		if !ok {
			s.logger.Errorf("non-channel item found in sensor event channel cache")
			return true
		}
		close(ch)
		return true
	})

	if s.rbReader != nil {
		s.rbReader.Close()
	}

	return nil
}

func (s *svc) eventLoop() error {
	recordChan := make(chan ringbuf.Record)
	done := false

	go func() {
		for {
			record, err := s.rbReader.Read()
			if done || errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			if err != nil {
				s.logger.Warnf("ringbuf read: %v", err)
				continue
			}
			recordChan <- record
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			done = true
			return nil
		case record := <-recordChan:
			// TODO: boottime timestamps
			event, err := types.Deserialize(s.logger, record.RawSample)
			if err != nil {
				s.logger.DPanicf("deserialize event: %v", err)
				continue
			}
			s.logger.Debugf("new event: %s(%s)", event.Meta.Type.String(), event.Meta.HookPoint.String())

			s.eventChannels.Range(func(k, v any) bool {
				select {
				case k.(chan<- types.Event) <- event:
				default:
					s.logger.Warnf("event channel is blocked, dropping event")
				}
				return true
			})
		}
	}
}
