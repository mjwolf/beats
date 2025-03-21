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

package conntrack

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/metricbeat/mb"
	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	_ "github.com/elastic/beats/v7/metricbeat/module/linux"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestData(t *testing.T) {
	f := mbtest.NewReportingMetricSetV2Error(t, getConfig())
	err := mbtest.WriteEventsReporterV2Error(f, t, ".")
	if err != nil {
		t.Fatal("write", err)
	}
}

func TestFetch(t *testing.T) {
	f := mbtest.NewReportingMetricSetV2Error(t, getConfig())
	events, errs := mbtest.ReportingFetchV2Error(f)

	assert.Empty(t, errs)
	if !assert.NotEmpty(t, events) {
		t.FailNow()
	}

	testConn := mapstr.M{
		"drop":           uint64(0),
		"early_drop":     uint64(0),
		"entries":        uint64(16),
		"found":          uint64(0),
		"ignore":         uint64(3271028),
		"insert_failed":  uint64(0),
		"invalid":        uint64(122),
		"search_restart": uint64(3),
	}

	rawEvent := events[0].BeatEvent("linux", "conntrack").Fields["linux"].(mapstr.M)["conntrack"].(mapstr.M)["summary"]

	assert.Equal(t, testConn, rawEvent)
}

func TestFetchConntrackModuleNotLoaded(t *testing.T) {
	// Create a temporary directory to simulate a missing /proc/net/stat/nf_conntrack file
	tmpDir := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "proc/net/stat"), 0755))
	c := getConfig()
	c["hostfs"] = tmpDir

	f := mbtest.NewReportingMetricSetV2Error(t, c)
	events, errs := mbtest.ReportingFetchV2Error(f)

	require.Len(t, errs, 1)
	err := errors.Join(errs...)
	assert.ErrorAs(t, err, &mb.PartialMetricsError{})
	assert.Contains(t, err.Error(), "error fetching conntrack stats: nf_conntrack kernel module not loaded")
	require.Empty(t, events)
}

func getConfig() map[string]interface{} {
	return map[string]interface{}{
		"module":     "linux",
		"metricsets": []string{"conntrack"},
		"hostfs":     "./_meta/testdata",
	}
}
