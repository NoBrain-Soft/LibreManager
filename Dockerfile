# syntax=docker/dockerfile:1
# Central server image: one binary, roles selected by the first argument
# (api | gateway | signer | init | migrate | all). All base images pinned by digest.

FROM node:22.23.4-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY api/openapi.yaml /src/api/openapi.yaml
COPY web/ ./
RUN npm run build

FROM golang:1.27.3-bookworm@sha256:b08bc99468058b6d8a0ada17fa54996b910d5e82a7e95bee0372e3bd98415258 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/ internal/server/webui/dist/
ARG VERSION=dev
ARG COMMIT=unknown
RUN go build -tags webui -ldflags "-s -w -X github.com/nobrain-soft/libremanager/internal/common/version.Version=${VERSION} -X github.com/nobrain-soft/libremanager/internal/common/version.Commit=${COMMIT}" \
      -o /out/stellwerk-server ./cmd/stellwerk-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/stellwerk-server /usr/bin/stellwerk-server
USER 65532:65532
ENTRYPOINT ["/usr/bin/stellwerk-server"]
CMD ["api"]
