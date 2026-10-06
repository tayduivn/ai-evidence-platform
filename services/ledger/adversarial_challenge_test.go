package ledger

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// CHALLENGE 1: QUEUE CONCURRENCY STRESS TESTS (100 PRODUCERS x 100 EVENTS = 10,000)
// ============================================================================

// TestAdversarial_QueueConcurrency_100Producers_10000Events tests 100 concurrent goroutines
// pushing 100 events each (total 10,000 events) into a BoundedQueue with plenty of capacity.
func TestAdversarial_QueueConcurrency_100Producers_10000Events(t *testing.T) {
	const numProducers = 100
	const eventsPerProducer = 100
	const totalEvents = numProducers * eventsPerProducer

	queue := NewBoundedQueue(20000, nil)
	defer queue.Close()

	var wg sync.WaitGroup
	startSignal := make(chan struct{})
	var enqueueErrors atomic.Uint64

	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal // synchronous start for maximum contention

			for j := 0; j < eventsPerProducer; j++ {
				ev := &AuditEventEnvelope{
					EventID:          fmt.Sprintf("adv-ev-%d-%d", workerID, j),
					CorrelationID:    fmt.Sprintf("corr-%d-%d", workerID, j),
					AISystemID:       "system-gpt-4o",
					CodeOrPromptHash: fmt.Sprintf("hash-%d-%d", workerID, j),
					Timestamp:        time.Now().UTC(),
				}
				if err := queue.Enqueue(ev); err != nil {
					enqueueErrors.Add(1)
				}
			}
		}(i)
	}

	start := time.Now()
	close(startSignal) // trigger all 100 producers simultaneously
	wg.Wait()
	duration := time.Since(start)

	stats := queue.Stats()
	t.Logf("Enqueued %d events across %d producers in %v (throughput: %.2f ops/sec)",
		stats.EnqueuedTotal, numProducers, duration, float64(stats.EnqueuedTotal)/duration.Seconds())

	if enqueueErrors.Load() != 0 {
		t.Fatalf("Expected 0 enqueue errors, got %d", enqueueErrors.Load())
	}
	if stats.EnqueuedTotal != uint64(totalEvents) {
		t.Fatalf("Expected %d enqueued events, got %d", totalEvents, stats.EnqueuedTotal)
	}
	if stats.DroppedTotal != 0 {
		t.Fatalf("Expected 0 dropped events, got %d", stats.DroppedTotal)
	}
	if queue.Len() != totalEvents {
		t.Fatalf("Expected queue.Len() == %d, got %d", totalEvents, queue.Len())
	}
}

// TestAdversarial_QueueConcurrency_WithDiskWAL_Saturation tests 100 concurrent goroutines
// pushing 10,000 events into a small BoundedQueue (capacity 1,000) backed by DiskWAL.
// It verifies high-water mark divert and zero loss under high contention.
func TestAdversarial_QueueConcurrency_WithDiskWAL_Saturation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_queue_wal_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	// Capacity 1,000, high-water mark 900
	queue := NewBoundedQueue(1000, wal)
	defer queue.Close()

	const numProducers = 100
	const eventsPerProducer = 100
	const totalEvents = numProducers * eventsPerProducer

	var wg sync.WaitGroup
	startSignal := make(chan struct{})
	var enqueueErrors atomic.Uint64

	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal

			for j := 0; j < eventsPerProducer; j++ {
				ev := &AuditEventEnvelope{
					EventID:       fmt.Sprintf("wal-ev-%d-%d", workerID, j),
					CorrelationID: fmt.Sprintf("corr-%d-%d", workerID, j),
					AISystemID:    "system-claude-3-5-sonnet",
					Timestamp:     time.Now().UTC(),
				}
				if err := queue.Enqueue(ev); err != nil {
					enqueueErrors.Add(1)
				}
			}
		}(i)
	}

	close(startSignal)
	wg.Wait()

	stats := queue.Stats()
	t.Logf("Stats: Enqueued=%d, DivertedWAL=%d, Dropped=%d, CurrentLen=%d",
		stats.EnqueuedTotal, stats.DivertedWAL, stats.DroppedTotal, stats.CurrentLength)

	if enqueueErrors.Load() != 0 {
		t.Fatalf("Expected 0 enqueue errors under WAL diversion, got %d", enqueueErrors.Load())
	}
	if stats.DroppedTotal != 0 {
		t.Fatalf("Expected 0 dropped events, got %d", stats.DroppedTotal)
	}
	totalAccounted := stats.EnqueuedTotal + stats.DivertedWAL
	if totalAccounted != uint64(totalEvents) {
		t.Fatalf("Expected total accounted %d, got %d (enqueued=%d, diverted=%d)",
			totalEvents, totalAccounted, stats.EnqueuedTotal, stats.DivertedWAL)
	}
	if stats.DivertedWAL == 0 {
		t.Fatalf("Expected DiskWAL diversion to occur when pushing 10,000 events into capacity 1,000")
	}
}

// TestAdversarial_FullPipeline_100Producers_WorkerConsumption tests the entire end-to-end pipeline:
// 100 producers push 10,000 events while MicroBatchWorker concurrently drains the queue,
// appends to Merkle Tree, and commits batches to MockImmudbClient.
func TestAdversarial_FullPipeline_100Producers_WorkerConsumption(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_pipe_wal_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	queue := NewBoundedQueue(15000, wal)
	defer queue.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	cfg := WorkerConfig{
		BatchSize:         100,
		FlushInterval:     10 * time.Millisecond,
		WALReplayInterval: 100 * time.Millisecond,
	}
	worker := NewMicroBatchWorker(cfg, queue, client, tree, wal)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker.Start(ctx)

	const numProducers = 100
	const eventsPerProducer = 100
	const totalEvents = numProducers * eventsPerProducer

	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal

			for j := 0; j < eventsPerProducer; j++ {
				ev := &AuditEventEnvelope{
					EventID:       fmt.Sprintf("pipe-ev-%d-%d", workerID, j),
					CorrelationID: fmt.Sprintf("corr-pipe-%d-%d", workerID, j),
					AISystemID:    "system-deepseek-r1",
					Timestamp:     time.Now().UTC(),
				}
				_ = queue.Enqueue(ev)
			}
		}(i)
	}

	close(startSignal)
	wg.Wait()

	// Allow worker time to drain queue and commit batches
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if worker.Tree().Size() >= int64(totalEvents) && client.TotalEvents() >= totalEvents {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	worker.Stop()

	t.Logf("Full pipeline results: Immudb TotalEvents=%d, Merkle Tree Leaves=%d, Worker Ingested=%d",
		client.TotalEvents(), worker.Tree().Size(), worker.eventsIngested.Load())

	if client.TotalEvents() != totalEvents {
		t.Fatalf("Expected immudb to contain %d events, got %d", totalEvents, client.TotalEvents())
	}
	if worker.Tree().Size() != int64(totalEvents) {
		t.Fatalf("Expected Merkle Tree to contain %d leaves, got %d", totalEvents, worker.Tree().Size())
	}

	// Verify cryptographic root hash is present
	root := worker.Tree().Root()
	var zeroRoot [32]byte
	if root == zeroRoot {
		t.Fatalf("Expected non-zero Merkle root hash")
	}

	// Verify Inclusion Proof for a random leaf in the 10,000 leaf tree
	proof, err := worker.Tree().InclusionProof(4242)
	if err != nil {
		t.Fatalf("Failed to generate inclusion proof for leaf 4242: %v", err)
	}
	leafHash, err := worker.Tree().LeafHashAt(4242)
	if err != nil {
		t.Fatalf("Failed to retrieve leaf hash at 4242: %v", err)
	}
	valid := VerifyInclusionProof(leafHash, root, proof.AuditPath)
	if !valid {
		t.Fatalf("Inclusion proof verification failed for leaf 4242: valid=false")
	}
}

// ============================================================================
// CHALLENGE 2: DISK WAL SEGMENT ROTATION, CRC32 INTEGRITY & CRASH REPLAY
// ============================================================================

// TestAdversarial_DiskWAL_MultiSegmentRotationAndCRC32 verifies segmented rotation
// with tiny thresholds, ensuring every single frame across multiple files has valid CRC32.
func TestAdversarial_DiskWAL_MultiSegmentRotationAndCRC32(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_wal_seg_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Threshold = 2KB to force rapid rotation
	wal, err := NewDiskWAL(tempDir, 2048)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}

	const numEvents = 200
	for i := 0; i < numEvents; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("seg-ev-%04d", i),
			CorrelationID: fmt.Sprintf("corr-seg-%04d", i),
			OutputPayload: "PAYLOAD_CONTENT_DESIGNED_TO_EXCEED_2KB_BOUNDARY_QUICKLY_1234567890",
			Timestamp:     time.Now().UTC(),
		}
		if err := wal.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent failed at index %d: %v", i, err)
		}
	}

	segCount := wal.ActiveSegmentFiles()
	t.Logf("Created %d segment files for %d events", segCount, numEvents)
	if segCount < 5 {
		t.Fatalf("Expected at least 5 segments, got %d", segCount)
	}
	_ = wal.Close()

	// Read each segment file independently and verify all frames
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	totalRecovered := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".log" {
			segPath := filepath.Join(tempDir, entry.Name())
			frames, err := ReadFrames(segPath)
			if err != nil {
				t.Fatalf("ReadFrames failed on %s: %v", entry.Name(), err)
			}
			totalRecovered += len(frames)
		}
	}

	if totalRecovered != numEvents {
		t.Fatalf("Expected %d total recovered events across segments, got %d", numEvents, totalRecovered)
	}
}

// TestAdversarial_DiskWAL_AdversarialCorruptionScenarios injects various forms of corruption
// into WAL files and verifies the error detection mechanisms.
func TestAdversarial_DiskWAL_AdversarialCorruptionScenarios(t *testing.T) {
	t.Run("InvalidMagicHeader", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv_corrupt_magic_*")
		defer os.RemoveAll(tempDir)

		wal, _ := NewDiskWAL(tempDir, 1024*1024)
		_ = wal.WriteEvent(&AuditEventEnvelope{EventID: "ev-magic-1"})
		_ = wal.Close()

		filePath := filepath.Join(tempDir, "wal-00000000.log")
		data, _ := os.ReadFile(filePath)
		// Corrupt magic bytes from WAL1 to BAD1
		data[0] = 'B'
		data[1] = 'A'
		data[2] = 'D'
		data[3] = '1'
		_ = os.WriteFile(filePath, data, 0644)

		_, err := ReadFrames(filePath)
		if !errors.Is(err, ErrCorruptFrame) {
			t.Fatalf("Expected ErrCorruptFrame on bad magic, got: %v", err)
		}
	})

	t.Run("PayloadBitFlipCRC32Mismatch", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv_corrupt_crc_*")
		defer os.RemoveAll(tempDir)

		wal, _ := NewDiskWAL(tempDir, 1024*1024)
		_ = wal.WriteEvent(&AuditEventEnvelope{EventID: "ev-crc-1", OutputPayload: "UNMODIFIED"})
		_ = wal.Close()

		filePath := filepath.Join(tempDir, "wal-00000000.log")
		data, _ := os.ReadFile(filePath)
		// Header is 12 bytes: flip bit in byte 13 (inside payload)
		data[13] ^= 0x01
		_ = os.WriteFile(filePath, data, 0644)

		_, err := ReadFrames(filePath)
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Expected ErrChecksumMismatch on bit flip, got: %v", err)
		}
	})

	t.Run("TruncatedFrameDuringPowerLoss", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv_corrupt_trunc_*")
		defer os.RemoveAll(tempDir)

		wal, _ := NewDiskWAL(tempDir, 1024*1024)
		_ = wal.WriteEvent(&AuditEventEnvelope{EventID: "ev-valid-1"})
		_ = wal.WriteEvent(&AuditEventEnvelope{EventID: "ev-valid-2"})
		_ = wal.Close()

		filePath := filepath.Join(tempDir, "wal-00000000.log")
		data, _ := os.ReadFile(filePath)

		// Append 7 bytes of a partial header (incomplete write during crash)
		truncated := append(data, []byte{0x57, 0x41, 0x4C, 0x31, 0x00, 0x00, 0x50}...)
		_ = os.WriteFile(filePath, truncated, 0644)

		frames, err := ReadFrames(filePath)
		if err != nil {
			t.Fatalf("ReadFrames should gracefully recover prior valid frames on truncation: %v", err)
		}
		if len(frames) != 2 {
			t.Fatalf("Expected 2 valid recovered frames, got %d", len(frames))
		}
	})
}

// TestAdversarial_DiskWAL_CrashRecoveryReplay_WithoutRotate stresses what happens
// when the system crashes abruptly while writing to the active segment (no clean Rotate()).
// Upon restart, does ReplayPending recover the uncommitted events from that active segment?
func TestAdversarial_DiskWAL_CrashRecoveryReplay_WithoutRotate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_wal_crash_replay_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Step 1: Process 1 starts, writes 10 events to active segment, and CRASHES (no Rotate)
	wal1, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}

	const eventsWritten = 10
	for i := 0; i < eventsWritten; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("crash-ev-%d", i),
			CorrelationID: fmt.Sprintf("corr-crash-%d", i),
			Timestamp:     time.Now().UTC(),
		}
		if err := wal1.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent failed: %v", err)
		}
	}

	// Simulate sudden crash: close file descriptor without calling Rotate()
	_ = wal1.Close()

	// Step 2: Process restarts (simulated by NewDiskWAL on the same directory)
	wal2, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Restarted NewDiskWAL failed: %v", err)
	}
	defer wal2.Close()

	// Step 3: Worker tries to replay pending segments
	var replayedEvents []*AuditEventEnvelope
	replayedCount, err := wal2.ReplayPending(func(batch []*AuditEventEnvelope) error {
		replayedEvents = append(replayedEvents, batch...)
		return nil
	})

	t.Logf("Crash recovery replay result: replayedCount=%d, err=%v (events originally written=%d)",
		replayedCount, err, eventsWritten)

	if replayedCount != eventsWritten {
		t.Errorf("EMPIRICAL DEFECT DETECTED: Expected %d events to be replayed after crash, but ReplayPending replayed %d! (Active segment was not replayed because seq < currentActiveSeq check excludes activeSeq)",
			eventsWritten, replayedCount)
	}
}

// ============================================================================
// CHALLENGE 3: RFC 3161 MOCK TSA FAULT INJECTION & ERROR HANDLING
// ============================================================================

// TestAdversarial_MockTSA_InvalidAlgorithmInjection tests TSA behavior when
// receiving a request with an unsupported or malicious digest algorithm.
func TestAdversarial_MockTSA_InvalidAlgorithmInjection(t *testing.T) {
	tsa, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer tsa.Close()

	rootHash := []byte("merkle-root-hash-32-bytes-long!")

	// Craft a request with an invalid algorithm OID (SHA-512 instead of SHA-256)
	oidSHA512 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	h := sha256.Sum256(rootHash)
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  oidSHA512,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: h[:],
		},
		Nonce:   big.NewInt(9999),
		CertReq: true,
	}

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		t.Fatalf("asn1.Marshal failed: %v", err)
	}

	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL: tsa.URL(),
		MaxRetries: 1,
	})

	respDER, err := client.postTimestampQuery(context.Background(), tsa.URL(), reqDER)
	if err != nil {
		t.Fatalf("postTimestampQuery failed: %v", err)
	}

	_, _, err = client.ValidateResponse(respDER, rootHash, big.NewInt(9999))
	if err == nil {
		t.Fatalf("Expected TSA rejection error for unsupported algorithm, got nil")
	}
	t.Logf("Expected rejection received for invalid algorithm: %v", err)
}

// TestAdversarial_MockTSA_CorruptedSignatureInjection verifies that corrupted cryptographic signatures
// are strictly rejected by the client validation logic.
func TestAdversarial_MockTSA_CorruptedSignatureInjection(t *testing.T) {
	tsa, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer tsa.Close()

	// Inject signature corruption into Mock TSA
	tsa.SetCorruptSignature(true)

	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL: tsa.URL(),
		MaxRetries: 1,
	})

	rootHash := []byte("root-hash-for-corrupt-sig-test")
	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash)
	if err == nil {
		t.Fatalf("Expected client to reject corrupted RSA signature, but RequestTimestamp succeeded!")
	}
	t.Logf("Client correctly rejected corrupted RSA signature: %v", err)
}

// TestAdversarial_MockTSA_ServerErrorInjection tests client resiliency when
// the TSA server responds with HTTP 500, HTTP 503, or rejects with PKIStatus.
func TestAdversarial_MockTSA_ServerErrorInjection(t *testing.T) {
	t.Run("HTTP500InternalServerError", func(t *testing.T) {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}))
		defer errServer.Close()

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL:  errServer.URL,
			HTTPTimeout: 1 * time.Second,
			MaxRetries:  2,
		})

		_, _, _, err := client.RequestTimestamp(context.Background(), []byte("root-hash"))
		if err == nil {
			t.Fatalf("Expected error when TSA returns HTTP 500, got nil")
		}
		t.Logf("Correctly handled HTTP 500 from TSA: %v", err)
	})

	t.Run("TSARejectionStatus", func(t *testing.T) {
		tsa, _ := NewMockTSAServer()
		defer tsa.Close()

		// Set PKIStatus = 2 (rejection)
		tsa.SetFailStatus(2)

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL: tsa.URL(),
			MaxRetries: 1,
		})

		_, _, _, err := client.RequestTimestamp(context.Background(), []byte("root-hash"))
		if err == nil {
			t.Fatalf("Expected error when TSA returns PKIStatus rejection, got nil")
		}
		t.Logf("Correctly handled PKIStatus rejection: %v", err)
	})

	t.Run("PrimaryEndpointFailsSecondarySucceeds", func(t *testing.T) {
		deadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		}))
		defer deadServer.Close()

		healthyTSA, _ := NewMockTSAServer()
		defer healthyTSA.Close()

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL:   deadServer.URL,
			SecondaryURL: healthyTSA.URL(),
			HTTPTimeout:  1 * time.Second,
			MaxRetries:   2,
		})

		rootHash := []byte("root-hash-fallback-test")
		_, tstInfo, _, err := client.RequestTimestamp(context.Background(), rootHash)
		if err != nil {
			t.Fatalf("Expected secondary TSA fallback to succeed, got: %v", err)
		}
		if tstInfo == nil {
			t.Fatalf("Expected valid TSTInfo from secondary TSA")
		}
		t.Logf("Fallback from dead primary to secondary TSA succeeded")
	})
}

// TestAdversarial_MockTSA_CertificateMissingEKUTimeStamping tests that the client
// rejects a TSA certificate that does NOT have the required id-kp-timeStamping extended key usage.
func TestAdversarial_MockTSA_CertificateMissingEKUTimeStamping(t *testing.T) {
	// Generate an RSA key and a certificate without ExtKeyUsageTimeStamping
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Missing TimeStamping!
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)

	// Create custom server with non-compliant certificate
	badTSA := &MockTSAServer{
		PrivateKey:  privKey,
		Certificate: cert,
		CertDER:     certDER,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/tsa", badTSA.Handler)
	badServer := httptest.NewServer(mux)
	badTSA.server = badServer
	defer badServer.Close()

	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL: badTSA.URL(),
		MaxRetries: 1,
	})

	rootHash := []byte("root-hash-invalid-cert-test")
	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash)
	if err == nil {
		t.Fatalf("Expected client to reject TSA certificate missing id-kp-timeStamping EKU, but it succeeded!")
	}
	t.Logf("Client correctly rejected certificate missing timeStamping EKU: %v", err)
}

// TestAdversarial_QueueCloseRaceCondition tests whether concurrent Enqueue
// during Close causes panics (such as send on closed channel).
func TestAdversarial_QueueCloseRaceCondition(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		queue := NewBoundedQueue(100, nil)

		var wg sync.WaitGroup
		const callers = 20

		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = queue.Enqueue(&AuditEventEnvelope{
						EventID: fmt.Sprintf("race-%d-%d", id, j),
					})
				}
			}(i)
		}

		time.Sleep(1 * time.Millisecond)
		_ = queue.Close()
		wg.Wait()
	}
}
