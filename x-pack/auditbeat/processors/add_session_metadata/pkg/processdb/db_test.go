// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package processdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFilteredExecutable(t *testing.T) {
	assert.Equal(t, true, isFilteredExecutable("runc"))
	assert.Equal(t, true, isFilteredExecutable("containerd-shim-v2-abcd"))
	assert.Equal(t, true, isFilteredExecutable("containerd-shim"))
	assert.Equal(t, true, isFilteredExecutable("calico-node"))
	assert.Equal(t, true, isFilteredExecutable("check-status"))
	assert.Equal(t, true, isFilteredExecutable("conmon"))
	assert.Equal(t, false, isFilteredExecutable("bash"))
}

func TestGetTtyType(t *testing.T) {
	assert.Equal(t, TtyConsole, getTtyType(4, 0))
	assert.Equal(t, Pts, getTtyType(136, 0))
	assert.Equal(t, Tty, getTtyType(4, 64))
	assert.Equal(t, TtyUnknown, getTtyType(1000, 1000))
}

func TestIsContainerRuntime(t *testing.T) {
	assert.Equal(t, true, isContainerRuntime("containerd-shim-v2-abcd"))
	assert.Equal(t, true, isContainerRuntime("containerd-shim"))
	assert.Equal(t, true, isContainerRuntime("runc"))
	assert.Equal(t, true, isContainerRuntime("conmon"))
	assert.Equal(t, false, isContainerRuntime("ls"))
}
