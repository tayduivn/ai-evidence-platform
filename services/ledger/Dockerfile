# ==============================================================================
# Stage 1: Build Binary
# ==============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY services/ledger/ services/ledger/

WORKDIR /src/services/ledger

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/ledger-worker ./cmd/ledger

# ==============================================================================
# Stage 2: Minimal Runtime Image
# ==============================================================================
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -S appgroup && adduser -S appuser -G appgroup && \
    mkdir -p /var/lib/ledger/wal && \
    chown -R appuser:appgroup /var/lib/ledger

WORKDIR /app
COPY --from=builder /bin/ledger-worker /usr/local/bin/ledger-worker

USER appuser
EXPOSE 8083

VOLUME ["/var/lib/ledger/wal"]

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
    CMD curl -f http://localhost:8083/health || exit 1

ENTRYPOINT ["/usr/local/bin/ledger-worker"]
