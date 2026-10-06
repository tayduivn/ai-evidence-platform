# ==============================================================================
# Stage 1: Build Binary
# ==============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy dependency modules
COPY services/ledger/ services/ledger/
COPY services/gateway/ services/gateway/

WORKDIR /src/services/gateway

# Build static binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/gateway ./cmd/gateway

# ==============================================================================
# Stage 2: Minimal Runtime Image
# ==============================================================================
FROM alpine:latest

# Install minimal certificates and tools for healthcheck probe
RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /bin/gateway /usr/local/bin/gateway

USER appuser
EXPOSE 8081

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
    CMD curl -f http://localhost:8081/health || exit 1

ENTRYPOINT ["/usr/local/bin/gateway"]
