FROM golang:1.22-bookworm AS build

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/stormlib-parity ./tools/paritycmd

FROM scratch
COPY --from=build /out/stormlib-parity /stormlib-parity
ENTRYPOINT ["/stormlib-parity"]
