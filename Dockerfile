# Dockerfile
# Stage 1: Build static Go binary
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Download dependencies with layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compile hardened static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/secretscanner \
    ./cmd/secretscanner

# Stage 2: Minimal non-root distroless runtime
FROM gcr.io/distroless/static-debian12:nonroot

USER 65532:65532
WORKDIR /scan

COPY --from=builder --chown=65532:65532 /bin/secretscanner /usr/local/bin/secretscanner

ENTRYPOINT ["/usr/local/bin/secretscanner"]
CMD ["-dir", "/scan"]
