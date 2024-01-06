package procfs_provider

import (
	"context"
	"reflect"
	"testing"

	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/procfs"

	"github.com/elastic/beats/v7/libbeat/beat"
	// "github.com/elastic/elastic-agent-libs/logp"
)

var (
	logger = *logp.NewLogger("procfs_test")
	timestamp = time.Now()
	execTests = []struct {
			in_event beat.Event
			procinfo []procfs.MockEntry
			out_event beat.Event
	}{
		{
			in_event: beat.Event{
				Timestamp: timestamp,
				Fields: mapstr.M{
					"process": mapstr.M {
						"pid": 100,
					},
				},
			},
			procinfo: []procfs.MockEntry{
				{
					Exe: "/bin/true",
					Environ: map[string]string{
						"User": "ubuntu",
					},
					Stat: procfs.Stat{
						PID: 100,
					},
					Cwd: "/tmp",
				},
			},
			out_event: beat.Event{
				Timestamp: timestamp,
				Fields: mapstr.M{
					"process": mapstr.M {
						"pid": 100,
					},
				},
			},
		},
	}
)

func TestExecEvent(t *testing.T) {
	for _, tt := range execTests {
		reader := procfs.NewMockReader()

		db := processdb.NewSimpleDB(reader, logger)

		for _, entry := range tt.procinfo {
			reader.AddEntry(uint32(entry.Stat.PID), entry)
		}

		provider, err := NewProvider(context.TODO(), logger, db, reader, "process.pid")
		assert.Nil(t, err, "error creating provider")

		provider.Start()

		provider.Update(&tt.in_event)

		if !reflect.DeepEqual(tt.in_event, tt.out_event) {
			t.Errorf("got %v, expected %v", tt.in_event, tt.out_event)
		}

		provider.Stop()
	}
}
