# ==============================================================================
# Stage 1: Build Binary
# ==============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy dependency modules
COPY services/ledger/ services/ledger/
COPY services/gateway/ services/gateway/
COPY services/approval/ services/approval/

WORKDIR /src/services/approval

# Build static binary with embedded web UI assets
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/approval ./cmd/approval

# ==============================================================================
# Stage 2: Minimal Runtime Image
# ==============================================================================
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /bin/approval /usr/local/bin/approval

USER appuser
EXPOSE 8082

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=5s \
    CMD curl -f http://localhost:8082/health || exit 1

ENTRYPOINT ["/usr/local/bin/approval"]
