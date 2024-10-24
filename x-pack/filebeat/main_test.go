// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
package main

// This file is mandatory as otherwise the filebeat.test binary is not generated correctly.
import (
	"flag"
	"os"
	"testing"

	"github.com/elastic/beats/v7/libbeat/cfgfile"
	cmd "github.com/elastic/beats/v7/libbeat/cmd"
	"github.com/elastic/beats/v7/libbeat/tests/system/template"
	fbcmd "github.com/elastic/beats/v7/x-pack/filebeat/cmd"
)

var (
	systemTest *bool
	fbCommand  *cmd.BeatsRootCmd
)

func init() {
	testing.Init()
	systemTest = flag.Bool("systemTest", false, "Set to true when running system tests")
	fbCommand = fbcmd.Filebeat()
	fbCommand.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("systemTest"))
	cfgfile.AddAllowedBackwardsCompatibleFlag("systemTest")
	fbCommand.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("test.coverprofile"))
	cfgfile.AddAllowedBackwardsCompatibleFlag("test.coverprofile")
}

// Test started when the test binary is started. Only calls main.
func TestSystem(t *testing.T) {
	cfgfile.ConvertFlagsForBackwardsCompatibility()
	if *systemTest {
		if err := fbCommand.Execute(); err != nil {
			os.Exit(1)
		}
	}
}

func TestTemplate(t *testing.T) {
	template.TestTemplate(t, fbCommand.Name(), true)
}
