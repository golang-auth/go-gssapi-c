current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
GO          ?= go
GOBIN ?= $(shell go env GOBIN)
TOOLBIN := $(current_dir)/toolbin


ifeq (${GOBIN},)
	GOBIN = $(shell go env GOPATH)/bin
endif


.DEFAULT: build

.PHONY: build
build: generate
	./scripts/gofmt

.PHONY: generate
generate: $(src_dir)/testvecs_test.go

$(src_dir)/testvecs_test.go: build-tools/mk-test-vectors
	$(GO) generate $(src_dir)/common_test.go


.PHONY: test
test:
	./scripts/gofmt
	${GO} test ./... -coverprofile=./cover.out -covermode=atomic


.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	@echo ------ golangci-lint
	@echo ------
	$(TOOLBIN)/golangci-lint run
	@echo -e "\n------ golangci-lint"
	@echo ------
	$(TOOLBIN)/staticcheck 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint $(TOOLBIN)/staticcheck
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint: | $(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1

$(TOOLBIN)/staticcheck: ~$(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install honnef.co/go/tools/cmd/staticcheck@2024.1