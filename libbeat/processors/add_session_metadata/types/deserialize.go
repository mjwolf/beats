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

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/pkg/endian"
	"github.com/elastic/elastic-agent-libs/logp"
)

func Deserialize(logger logp.Logger, raw []byte) (Event, error) {
	var eventWithMeta Event
	r := bytes.NewReader(raw)

	if err := deserializeMeta(r, &eventWithMeta.Meta); err != nil {
		return Event{}, err
	}

	switch eventWithMeta.Meta.Type {
	case ProcessFork:
		event := ProcessForkEvent{}

		if err := deserializePidInfo(r, &event.ParentPids); err != nil {
			return Event{}, err
		}

		if err := deserializePidInfo(r, &event.ChildPids); err != nil {
			return Event{}, err
		}

		if err := deserializeCredInfo(r, &event.Creds); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, fmt.Errorf("failed to deserialize fork event: %s", err.Error())
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case ProcessExec:
		event := ProcessExecEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		if err := deserializeCredInfo(r, &event.Creds); err != nil {
			return Event{}, err
		}

		if err := deserializeTtyDev(r, &event.CTty); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, fmt.Errorf("failed to deserialize exec event: %s", err.Error())
		}

		if val, ok := varlen[Cwd]; ok {
			event.Cwd = val.(string)
		}

		if val, ok := varlen[Argv]; ok {
			event.Argv = val.([]string)
		}

		if val, ok := varlen[Env]; ok {
			event.Env = val.(map[string]string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case ProcessExit:
		event := ProcessExitEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		if err := binary.Read(r, endian.Native, &event.ExitCode); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case ProcessSetsid:
		event := ProcessSetsidEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case FileCreateExecutable:
		event := FileCreateExecutableEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case FileModifyExecutable:
		event := FileModifyExecutableEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case FileCreateFile:
		event := FileCreateFileEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case FileModifyFile:
		event := FileModifyFileEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	case FileDeleteFile:
		event := FileDeleteFileEvent{}

		if err := deserializePidInfo(r, &event.Pids); err != nil {
			return Event{}, err
		}

		varlen, err := deserializeVarlenFields(r)
		if err != nil {
			return Event{}, err
		}

		if val, ok := varlen[PidsSsCgroupPath]; ok {
			event.PidsSsCgroupPath = val.(string)
		}

		if val, ok := varlen[Filename]; ok {
			event.Filename = val.(string)
		}

		eventWithMeta.Body = event
		return eventWithMeta, nil
	default:
		logger.DPanicf("unknown event type: %d", eventWithMeta.Meta.Type)
		return Event{}, fmt.Errorf("unknown event type: %d", eventWithMeta.Meta.Type)
	}
}

func deserializeMeta(r *bytes.Reader, m *Meta) error {
	if err := binary.Read(r, endian.Native, &m.Type); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &m.TimestampNs); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &m.HookPoint); err != nil {
		return err
	}

	return nil
}

func deserializePidInfo(r *bytes.Reader, out *PidInfo) error {
	if err := binary.Read(r, endian.Native, &out.StartTimeNs); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Tid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Tgid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Vpid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Ppid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Pgid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Sid); err != nil {
		return err
	}

	return nil
}

func deserializeCredInfo(r *bytes.Reader, out *CredInfo) error {
	if err := binary.Read(r, endian.Native, &out.Ruid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Rgid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Euid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Egid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Suid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Sgid); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.CapPermitted); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.CapEffective); err != nil {
		return err
	}

	return nil
}

func deserializeTtyDev(r *bytes.Reader, out *TtyDev) error {
	if err := binary.Read(r, endian.Native, &out.Minor); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Major); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Winsize.Rows); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Winsize.Cols); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Termios.CIflag); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Termios.COflag); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Termios.CLflag); err != nil {
		return err
	}

	if err := binary.Read(r, endian.Native, &out.Termios.CCflag); err != nil {
		return err
	}

	return nil
}

type varlenStart struct {
	nfields uint32
	size    uint64
}

type varlenField struct {
	typ  Field
	size uint32
}

func deserializeVarlenStart(r *bytes.Reader) (varlenStart, error) {
	var ret varlenStart
	if err := binary.Read(r, endian.Native, &ret.nfields); err != nil {
		return varlenStart{}, err
	}

	if err := binary.Read(r, endian.Native, &ret.size); err != nil {
		return varlenStart{}, err
	}

	return ret, nil
}

func deserializeVarlenFieldHeader(r *bytes.Reader) (varlenField, error) {
	var ret varlenField
	if err := binary.Read(r, endian.Native, &ret.typ); err != nil {
		return varlenField{}, err
	}

	if err := binary.Read(r, endian.Native, &ret.size); err != nil {
		return varlenField{}, err
	}

	return ret, nil
}

func deserializeVarlenFields(r *bytes.Reader) (VarlenMap, error) {
	start, err := deserializeVarlenStart(r)
	if err != nil {
		return nil, err
	}

	ret := make(VarlenMap)
	for i := uint32(0); i < start.nfields; i++ {
		varlenField, err := deserializeVarlenFieldHeader(r)
		if err != nil {
			return nil, err
		}

		switch varlenField.typ {
		case Cwd, Filename, PidsSsCgroupPath:
			str, err := deserializeVarlenString(r, varlenField.size)
			if err != nil {
				return nil, err
			}

			ret[varlenField.typ] = str
		case Argv:
			argv, err := deserializeVarlenArgv(r, varlenField.size)
			if err != nil {
				return nil, err
			}

			ret[Argv] = argv
		case Env:
			env, err := deserializeVarlenEnv(r, varlenField.size)
			if err != nil {
				return nil, err
			}

			ret[Env] = env
		default:
			return nil, fmt.Errorf("unsupported varlen type: %d", varlenField.typ)
		}
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("data left in reader: %v", r.Len())
	}

	return ret, nil
}

func deserializeVarlenString(r *bytes.Reader, size uint32) (string, error) {
	if size == 0 {
		return "", nil
	}

	b := strings.Builder{}
	b.Grow(int(size - 1))
	for i := uint32(0); i < size-1; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		err = b.WriteByte(c)
		if err != nil {
			return "", err
		}
	}

	// read null terminator
	_, err := r.ReadByte()
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func deserializeVarlenArgv(r *bytes.Reader, size uint32) ([]string, error) {
	b := strings.Builder{}
	b.Grow(int(size))

	var ret []string
	for i := uint32(0); i < size; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		if c == 0 {
			ret = append(ret, b.String())
			b.Reset()
		} else {
			err = b.WriteByte(c)
			if err != nil {
				return nil, err
			}
		}
	}

	return ret, nil
}

func deserializeVarlenEnv(r *bytes.Reader, size uint32) (map[string]string, error) {
	key := strings.Builder{}
	value := strings.Builder{}

	parsingKey := true
	ret := make(map[string]string)
	for i := uint32(0); i < size; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		switch c {
		case 0:
			ret[key.String()] = value.String()
			key.Reset()
			value.Reset()
			parsingKey = true
		case '=':
			parsingKey = false
		default:
			if parsingKey {
				err = key.WriteByte(c)
				if err != nil {
					return nil, err
				}
			} else {
				err = value.WriteByte(c)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return ret, nil
}
