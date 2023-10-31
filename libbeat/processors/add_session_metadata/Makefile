BUILD_ARCH ?= amd64

DEBUG_POLICY ?= 1

CLANG=clang
CFLAGS := -O2 -g -Wall $(CFLAGS)

.PHONY: generate
make generate:
	BPF_CLANG=$(CLANG) BPF_CFLAGS="$(CFLAGS) -DDEBUG_POLICY=$(DEBUG_POLICY)" BPF_TARGET=$(BUILD_ARCH) go generate provider/ebpf/provider.go
	go generate types/events.go

