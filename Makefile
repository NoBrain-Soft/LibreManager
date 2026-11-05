# Stellwerk build targets (CLAUDE.md "Commands").
SHELL := /bin/bash
GO ?= go
GOBIN ?= $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/nobrain-soft/libremanager/internal/common/version.Version=$(VERSION) \
           -X github.com/nobrain-soft/libremanager/internal/common/version.Commit=$(COMMIT) \
           -X github.com/nobrain-soft/libremanager/internal/common/version.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
ARCHES ?= amd64 arm64
TEST_DB ?= postgres://stellwerk:stellwerk-dev@127.0.0.1:5432/stellwerk?sslmode=disable
DEV_ENV := STELLWERK_DATABASE_URL=$(TEST_DB) STELLWERK_SECRETS_DIR=$(CURDIR)/.dev/secrets \
           STELLWERK_DATA_DIR=$(CURDIR)/.dev/data STELLWERK_RUN_DIR=$(CURDIR)/.dev/run \
           STELLWERK_PUBLIC_URL=http://localhost:5173 STELLWERK_AGENT_ENDPOINT=localhost:8443 \
           STELLWERK_API_LISTEN=127.0.0.1:8080 STELLWERK_GATEWAY_LISTEN=127.0.0.1:8443 \
           STELLWERK_LOG_FORMAT=text
WEBUI_DIST := internal/server/webui/dist

.PHONY: all build web web-embed server agent helper test test-go test-web lint gen gen-check dev dev-deps \
        agent-bench packages e2e image clean tools

all: lint test build

## tools: install pinned codegen/lint tools into GOBIN
tools:
	$(GO) install github.com/bufbuild/buf/cmd/buf@v1.75.0
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
	$(GO) install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2
	CGO_ENABLED=1 $(GO) install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

## gen: regenerate protobuf, OpenAPI server stubs, sqlc queries and the TS client
gen:
	buf generate
	oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
	sqlc generate
	cd web && npm run gen:api

## gen-check: fail if generated code is out of date (CI)
gen-check: gen
	git diff --exit-code -- internal/proto internal/server/api/apigen internal/server/store/db web/src/api

web:
	cd web && npm ci --no-audit --no-fund && npm run build

web-embed: web
	find $(WEBUI_DIST) -mindepth 1 ! -name .gitkeep -delete
	cp -r web/dist/. $(WEBUI_DIST)/

server: web-embed
	CGO_ENABLED=0 $(GO) build -trimpath -tags webui -ldflags "$(LDFLAGS)" -o bin/stellwerk-server ./cmd/stellwerk-server

agent helper:
	@for a in $(ARCHES); do \
	  echo "building agent for linux/$$a"; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux_$$a/stellwerk-agent ./cmd/stellwerk-agent || exit 1; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux_$$a/stellwerk-agent-helper ./cmd/stellwerk-agent-helper || exit 1; \
	done

build: server agent

## test: Go tests (DB tests need STELLWERK_TEST_DATABASE_URL) + web tests
test: test-go test-web

test-go:
	$(GO) test -race -count=1 ./...

test-web:
	cd web && npm test

## lint: golangci-lint, buf lint, eslint + tsc
lint:
	golangci-lint run ./...
	buf lint
	cd web && npm run lint && npm run typecheck

## dev-deps: start PostgreSQL + VictoriaMetrics for development
dev-deps:
	docker compose -f deploy/dev/compose.yml up -d --wait

## dev: deps in containers, `server all` + Vite dev server natively
dev: dev-deps
	mkdir -p .dev
	$(DEV_ENV) $(GO) run ./cmd/stellwerk-server init
	@echo "UI: http://localhost:5173 (Vite dev server proxies /api to :8080)"
	@trap 'kill 0' INT TERM; \
	  $(DEV_ENV) $(GO) run ./cmd/stellwerk-server all & \
	  (cd web && npm install --no-audit --no-fund && npm run dev) & \
	  wait

## agent-bench: enforce the agent resource budget (binary size, RSS, CPU)
agent-bench:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/bench/stellwerk-agent ./cmd/stellwerk-agent
	@size=$$(stat -c %s bin/bench/stellwerk-agent); limit=$$((20*1024*1024)); \
	  echo "agent binary: $$((size/1024/1024)) MiB (limit 20 MiB)"; \
	  [ $$size -le $$limit ] || { echo "binary over budget"; exit 1; }
	bin/bench/stellwerk-agent bench --duration 60s --interval 1s

## packages: .deb + .rpm via nfpm (amd64 + arm64) into dist/
packages: agent
	@mkdir -p dist
	@for a in $(ARCHES); do \
	  rpmarch=$$( [ $$a = amd64 ] && echo x86_64 || echo aarch64 ); \
	  for fmt in deb rpm; do \
	    ARCH=$$a VERSION=$${VERSION#v} $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0 pkg \
	      --config deploy/packaging/nfpm.yaml --packager $$fmt --target dist/ || exit 1; \
	  done; \
	  cp dist/stellwerk-agent_*_$$a.deb dist/stellwerk-agent_latest_$$a.deb; \
	  cp dist/stellwerk-agent-*.$$rpmarch.rpm dist/stellwerk-agent-latest.$$rpmarch.rpm 2>/dev/null || true; \
	done
	@cd dist && for f in *latest*.deb *latest*.rpm; do sha256sum $$f > $$f.sha256; done
	@echo "copy dist/stellwerk-agent* to /opt/stellwerk/data/packages on the central node"

## image: build the central server container image
image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t stellwerk-server:$(VERSION) .

## e2e: VM-based end-to-end tests (Incus); see test/e2e/README.md
e2e:
	test/e2e/run.sh

clean:
	$(GO) clean -testcache
	find bin dist .dev web/dist -mindepth 0 -delete 2>/dev/null || true
