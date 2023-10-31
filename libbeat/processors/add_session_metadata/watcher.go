package add_session_metadata

import (
	"context"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/provider"
	"github.com/elastic/beats/v7/libbeat/processors/add_session_metadata/types"
)

type Watcher struct {
	ctx context.Context
	db processdb.DB
	ch <-chan types.Event
	logger *logp.Logger
}

func NewWatcher(ctx context.Context, logger *logp.Logger, db processdb.DB, p provider.Provider) (Watcher) {
	w := Watcher {
		ctx: ctx,
		logger: logger,
		db: db,
		ch: p.CreateEventChannel(1024),
	}
	return w
}

// Watch for events from the process event provider, and add them to the process DB
func (w *Watcher) eventLoop() {
	for {
		select {
		case <-w.ctx.Done():
			//TODO: finish processing any events in channel
			return
		case event := <-w.ch:
			w.logger.Debugf("got event in watcher! %v", event)

			switch event.Meta.Type {
			case types.ProcessExec:
				processExec, ok := event.Body.(types.ProcessExecEvent)
				if !ok {
					w.logger.Errorf("malformed process exec event")
					continue
				}
				w.db.InsertExec(processExec)
				w.logger.Errorf("inserted pid %v in db", processExec.Pids.Tgid)
			default:
				w.logger.Debugf("got unknown event type")
			}
		}
	}
}

func (w *Watcher) Start() error {
	go func() {
		w.eventLoop()
	}()
	return nil
}

func (w *Watcher) Stop() error {
	w.ctx.Done()
	return nil
}
