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

package processors

import (
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/conditions"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

// NewConditional returns a constructor suitable for registering when conditionals as a plugin.
func NewConditional(
	ruleFactory Constructor,
) Constructor {
	return func(cfg *config.C, log *logp.Logger) (beat.Processor, error) {
		rule, err := ruleFactory(cfg, log)
		if err != nil {
			return nil, err
		}

		return addCondition(cfg, rule, log)
	}
}

// WhenProcessor is a tuple of condition plus a Processor.
type WhenProcessor struct {
	condition conditions.Condition
	p         beat.Processor
}

// NewConditionRule returns a processor that will execute the provided processor if the condition is true.
func NewConditionRule(
	c conditions.Config,
	p beat.Processor,
	log *logp.Logger,
) (beat.Processor, error) {
	cond, err := conditions.NewCondition(&c, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize condition: %w", err)
	}

	if cond == nil {
		return p, nil
	}
	return &WhenProcessor{cond, p}, nil
}

// Run executes this WhenProcessor.
func (r *WhenProcessor) Run(event *beat.Event) (*beat.Event, error) {
	if !(r.condition).Check(event) {
		return event, nil
	}
	return r.p.Run(event)
}

func (r *WhenProcessor) String() string {
	return fmt.Sprintf("%v, condition=%v", r.p.String(), r.condition.String())
}

func addCondition(
	cfg *config.C,
	p beat.Processor,
	log *logp.Logger,
) (beat.Processor, error) {
	if !cfg.HasField("when") {
		return p, nil
	}
	sub, err := cfg.Child("when", -1)
	if err != nil {
		return nil, err
	}

	condConfig := conditions.Config{}
	if err := sub.Unpack(&condConfig); err != nil {
		return nil, err
	}

	return NewConditionRule(condConfig, p, log)
}

type ifThenElseConfig struct {
	Cond conditions.Config `config:"if"   validate:"required"`
	Then *config.C         `config:"then" validate:"required"`
	Else *config.C         `config:"else"`
}

// IfThenElseProcessor executes one set of processors (then) if the condition is
// true and another set of processors (else) if the condition is false.
type IfThenElseProcessor struct {
	cond conditions.Condition
	then *Processors
	els  *Processors
}

// NewIfElseThenProcessor construct a new IfThenElseProcessor.
func NewIfElseThenProcessor(cfg *config.C, logger *logp.Logger) (*IfThenElseProcessor, error) {
	var c ifThenElseConfig
	if err := cfg.Unpack(&c); err != nil {
		return nil, err
	}

	cond, err := conditions.NewCondition(&c.Cond, logger)
	if err != nil {
		return nil, err
	}

	newProcessors := func(c *config.C) (*Processors, error) {
		if c == nil {
			return nil, nil
		}
		if !c.IsArray() {
			return New([]*config.C{c}, logger)
		}

		var pc PluginConfig
		if err := c.Unpack(&pc); err != nil {
			return nil, err
		}
		return New(pc, logger)
	}

	var ifProcessors, elseProcessors *Processors
	if ifProcessors, err = newProcessors(c.Then); err != nil {
		return nil, err
	}
	if elseProcessors, err = newProcessors(c.Else); err != nil {
		return nil, err
	}

	return &IfThenElseProcessor{cond, ifProcessors, elseProcessors}, nil
}

// Run checks the if condition and executes the processors attached to the
// then statement or the else statement based on the condition.
func (p *IfThenElseProcessor) Run(event *beat.Event) (*beat.Event, error) {
	if p.cond.Check(event) {
		return p.then.Run(event)
	} else if p.els != nil {
		return p.els.Run(event)
	}
	return event, nil
}

func (p *IfThenElseProcessor) String() string {
	var sb strings.Builder
	sb.WriteString("if ")
	sb.WriteString(p.cond.String())
	sb.WriteString(" then ")
	sb.WriteString(p.then.String())
	if p.els != nil {
		sb.WriteString(" else ")
		sb.WriteString(p.els.String())
	}
	return sb.String()
}
