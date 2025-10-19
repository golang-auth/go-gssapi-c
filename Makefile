current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
GO          ?= go
TOOLBIN := $(current_dir)/toolbin

src_dir = $(current_dir)


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
	${GO} test -asan ./... -coverprofile=cover.out -covermode=atomic
	${GO} tool cover -html=cover.out -o coverage.html

.PHONY: gdb
gdb:
	GO_CFLAGS="-g" $(GO) test -c  -timeout 30s
	gdb ./go-gssapi-c.test

.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint $(TOOLBIN)/staticcheck
	@echo ------ golangci-lint
	@echo ------
	$(TOOLBIN)/golangci-lint run
	@echo -e "\n------ staticcheck"
	@echo ------
	$(TOOLBIN)/staticcheck 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint $(TOOLBIN)/staticcheck
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint: | $(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2

$(TOOLBIN)/staticcheck: ~$(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install honnef.co/go/tools/cmd/staticcheck@2025.1.1
