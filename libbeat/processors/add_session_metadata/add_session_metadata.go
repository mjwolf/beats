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

package add_session_metadata

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/elastic/elastic-agent-libs/monitoring"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/pkg/processdb"
	jsprocessor "github.com/elastic/beats/v7/libbeat/processors/script/javascript/module/processor"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const processorName = "add_session_metadata"
const logName = "processor." + processorName

var (
	reg *monitoring.Registry
)

func init() {
	processors.RegisterPlugin(processorName, New)
	jsprocessor.RegisterPlugin("AddSessionMetadata", New)

	reg = monitoring.Default.NewRegistry(logName, monitoring.DoNotReport)
}

type addSessionMetadata struct {
	config Config
	logger *logp.Logger
	db processdb.DB
}

func New(cfg *config.C) (beat.Processor, error) {

	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("fail to unpack the %v configuration: %w", processorName, err)
	}

	logger := logp.NewLogger(logName)

	p := &addSessionMetadata{
		config: c,
		logger: logger,
		db: processdb.NewSimpleDB(*logger),
	}

	return p, nil
}

func (p *addSessionMetadata) Run(event *beat.Event) (*beat.Event, error) {
	if !p.config.ReplaceFields {
		return event, nil
	}

	result, err := p.enrich(event)
	if err != nil {
		return nil, fmt.Errorf("enriching event %v: %w", event, err)
	}

	event = result

	return event, nil
}

func (p *addSessionMetadata) String() string {
	return fmt.Sprintf("%v=[]", processorName)
}

func pidToInt(value interface{}) (pid uint32, err error) {
	switch v := value.(type) {
	case string:
		pid, err = strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("error converting string to integer: %w", err)
		}
	case int:
		pid = v
	case int8, int16, int32, int64:
		pid64 := reflect.ValueOf(v).Int()
		if pid = int(pid64); int64(pid) != pid64 {
			return 0, fmt.Errorf("integer out of range: %d", pid64)
		}
	case uint, uintptr, uint8, uint16, uint32, uint64:
		pidu64 := reflect.ValueOf(v).Uint()
		if pid = int(pidu64); pid < 0 || uint64(pid) != pidu64 {
			return 0, fmt.Errorf("integer out of range: %d", pidu64)
		}
	default:
		return 0, fmt.Errorf("not an integer or string, but %T", v)
	}
	return pid, nil
}

func (p *addSessionMetadata) enrich(event *beat.Event) (*beat.Event, error) {
	pidIf, err := event.GetValue("process.pid")
	if err != nil {
		return nil, err
	}

	pid, err := pidToInt(pidIf)
	if err != nil {
		return nil, fmt.Errorf("cannot parse pid field '%s': %w", pidField, err)
	}

	fullProcess, err := p.db.GetProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("pid %v not found in db: %w", pid, err)
	}

	p.logger.Debugf("got fullProcess for pid %v: %v", pid, fullProcess)
	return event, nil
}
