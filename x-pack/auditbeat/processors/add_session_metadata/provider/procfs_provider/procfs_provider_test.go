package procfs_provider

import (
	"context"
	"testing"

	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/processdb"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/pkg/procfs"
	"github.com/elastic/beats/v7/x-pack/auditbeat/processors/add_session_metadata/types"

	"github.com/elastic/beats/v7/libbeat/beat"
	// "github.com/elastic/elastic-agent-libs/logp"
)

var (
	logger = *logp.NewLogger("procfs_test")
	timestamp = time.Now()
	execTests = []struct {
			pid uint32
			in_event beat.Event
			prereq []procfs.ProcessInfo
			procinfo []procfs.ProcessInfo
			expected types.Process
	}{
		{
			pid: 100,
			// in_event is the event that will be passed into Update
			in_event: beat.Event{
				Timestamp: timestamp,
				Fields: mapstr.M{
					"auditd": mapstr.M{
						"data": mapstr.M {
							"a0": "aaaad2e476e0",
							"a1": "aaaad2dd07a0",
							"a2": "aaaad3170490",
							"a3": "ffff85911b40",
							"arch": "aarch64",
							"argc": "1",
							"syscall": "execve",
							"tty": "pts4",
						},
					},
					"process": mapstr.M {
						"pid": 100,
						"args": "whoami",
						"executable": "/usr/bin/whoami",
						"name": "whoami",
						"working_directory": "/",
					},
				},
			},
			// procinfo is list of mocked procfs data
			prereq: []procfs.ProcessInfo{
				{
					Pids: types.PidInfo{
						StartTimeNs: 0,
						Tid: 80,
						Tgid: 80,
						Vpid: 0,
						Ppid: 60,
						Pgid: 80,
						Sid: 60,
					},
				},
			},
			procinfo: []procfs.ProcessInfo{
				{
					Pids: types.PidInfo{
						StartTimeNs: 0,
						Tid: 100,
						Tgid: 100,
						Vpid: 0,
						Ppid: 80,
						Pgid: 100,
						Sid: 60,
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
		for _, entry := range tt.prereq {
			reader.AddEntry(uint32(entry.Pids.Tgid), entry)
		}
		db.ScrapeProcfs()

		for _, entry := range tt.procinfo {
			reader.AddEntry(uint32(entry.Pids.Tgid), entry)
		}

		provider, err := NewProvider(context.TODO(), logger, db, reader, "process.pid")
		assert.Nil(t, err, "error creating provider")

		provider.Start()

		provider.UpdateDB(&tt.in_event)

		actual, err := db.GetProcess(tt.pid)
		if err != nil {
			assert.Fail(t, "pid not found in db")
		}

		assert.Equal(t, uint32(80), actual.Parent.PID)
		//if !reflect.DeepEqual(tt.expected, actual) {
		//	t.Errorf("\nexpected:\n%v\n\nactual:\n%v\n", tt.expected, actual)
		//}

		provider.Stop()
	}
}
