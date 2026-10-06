package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// StreamPassThrough streams chunks from upstream directly to client with zero latency buffering,
// concurrently accumulating tokens in-flight for audit evidence generation.
func (p *ProxyHandler) StreamPassThrough(
	ctx context.Context,
	w http.ResponseWriter,
	upstreamBody io.ReadCloser,
	acc *SSEAccumulator,
) (AccumulatorResult, error) {
	defer upstreamBody.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported: ResponseWriter does not implement http.Flusher", http.StatusInternalServerError)
		return AccumulatorResult{}, errors.New("flusher unsupported")
	}

	// Set unbuffered SSE response headers
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)
	buf := *bufPtr

	status := "COMPLETED"

	for {
		select {
		case <-ctx.Done():
			// Client disconnected early
			status = "CLIENT_DISCONNECTED"
			return acc.Finalize(status), ctx.Err()
		default:
		}

		n, err := upstreamBody.Read(buf)
		if n > 0 {
			chunk := buf[:n]

			// Write to client and flush immediately
			if _, writeErr := w.Write(chunk); writeErr != nil {
				status = "CLIENT_DISCONNECTED"
				return acc.Finalize(status), writeErr
			}
			flusher.Flush()

			// Fork chunk to in-flight accumulator
			acc.ProcessBytes(chunk)
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				status = "CLIENT_DISCONNECTED"
				return acc.Finalize(status), err
			}
			// Upstream connection aborted
			status = "UPSTREAM_ERROR"
			return acc.Finalize(status), err
		}
	}

	return acc.Finalize(status), nil
}
