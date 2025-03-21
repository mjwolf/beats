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

package beater

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/elastic/beats/v7/winlogbeat/checkpoint"
)

type eventACKer struct {
	active     *atomic.Int64
	wg         *sync.WaitGroup
	checkpoint *checkpoint.Checkpoint
}

func newEventACKer(checkpoint *checkpoint.Checkpoint) *eventACKer {
	return &eventACKer{
		active:     &atomic.Int64{},
		wg:         &sync.WaitGroup{},
		checkpoint: checkpoint,
	}
}

// ACKEvents receives callbacks from the publisher for every event that is
// published. It persists the record number of the last event in each
func (a *eventACKer) ACKEvents(data []interface{}) {
	states := make(map[string]*checkpoint.EventLogState)

	for _, datum := range data {
		if st, ok := datum.(checkpoint.EventLogState); ok {
			states[st.Name] = &st
		}
	}

	for _, st := range states {
		a.checkpoint.PersistState(*st)
	}

	// Mark events as done (subtract).
	a.active.Add(-1 * int64(len(data)))
	a.wg.Add(-1 * len(data))
}

// Wait waits for all events to be ACKed or for the context to be done.
func (a *eventACKer) Wait(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		a.wg.Wait()
	}()
	<-ctx.Done()
}

// Add adds to the number of active events.
func (a *eventACKer) Add(delta int) {
	a.active.Add(int64(delta))
	a.wg.Add(delta)
}

// Active returns the number of active events (published but not yet ACKed).
func (a *eventACKer) Active() int {
	return int(a.active.Load())
}
