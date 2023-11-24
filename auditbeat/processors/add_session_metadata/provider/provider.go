package provider

import (
	"github.com/elastic/beats/v7/auditbeat/processors/add_session_metadata/types"
)

type Provider interface {
	Start() error
	Stop() error
	CreateEventChannel(bufferSize uint32) <-chan types.Event
}
