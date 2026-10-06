package dualmode

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_DecisionStore_100WorkersConcurrentStress tests MemoryDecisionStore under 100 concurrent workers.
func TestAdversarial_DecisionStore_100WorkersConcurrentStress(t *testing.T) {
	store := NewMemoryDecisionStore()
	numWorkers := 100
	opsPerWorker := 50

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	var (
		totalSaves   int64
		totalGets    int64
		totalUpdates int64
		totalLists   int64
		totalErrors  int64
	)

	// Prepopulate 20 common records for shared contentious updates
	sharedIDs := make([]string, 20)
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("shared-rec-%03d", i)
		sharedIDs[i] = id
		_ = store.Save(&DecisionRecord{
			DecisionID:    id,
			CorrelationID: fmt.Sprintf("corr-%03d", i),
			AISystemID:    "credit-advisor-v1",
			SystemType:    "llm",
			Status:        StatusPending,
			ExpiresAt:     time.Now().UTC().Add(10 * time.Minute),
		})
	}

	startSignal := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			<-startSignal

			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for op := 0; op < opsPerWorker; op++ {
				action := rng.Intn(4)
				switch action {
				case 0:
					// Save a private record
					recID := fmt.Sprintf("worker-%03d-rec-%04d", workerID, op)
					err := store.Save(&DecisionRecord{
						DecisionID:    recID,
						CorrelationID: fmt.Sprintf("corr-%s", recID),
						AISystemID:    "credit-advisor-v1",
						SystemType:    "llm",
						Status:        StatusPending,
						ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
					})
					if err != nil {
						atomic.AddInt64(&totalErrors, 1)
					}
					atomic.AddInt64(&totalSaves, 1)

				case 1:
					// Query either shared or private record
					targetID := sharedIDs[rng.Intn(len(sharedIDs))]
					rec, err := store.Get(targetID)
					if err != nil {
						atomic.AddInt64(&totalErrors, 1)
					} else if rec == nil || rec.DecisionID != targetID {
						t.Errorf("corrupt record retrieved for ID %s: %+v", targetID, rec)
						atomic.AddInt64(&totalErrors, 1)
					}
					atomic.AddInt64(&totalGets, 1)

				case 2:
					// Contended update on shared records
					targetID := sharedIDs[rng.Intn(len(sharedIDs))]
					newStatus := StatusApproved
					if rng.Intn(2) == 0 {
						newStatus = StatusAwaitingSecond
					}
					err := store.UpdateStatus(targetID, newStatus)
					if err != nil {
						atomic.AddInt64(&totalErrors, 1)
					}
					atomic.AddInt64(&totalUpdates, 1)

				case 3:
					// Concurrent List
					list := store.List()
					if len(list) < len(sharedIDs) {
						t.Errorf("expected at least %d records, got %d", len(sharedIDs), len(list))
						atomic.AddInt64(&totalErrors, 1)
					}
					atomic.AddInt64(&totalLists, 1)
				}
			}
		}()
	}

	// Trigger all 100 workers at once
	close(startSignal)
	wg.Wait()

	t.Logf("Stress test complete with 100 workers: Saves=%d, Gets=%d, Updates=%d, Lists=%d, Errors=%d",
		totalSaves, totalGets, totalUpdates, totalLists, totalErrors)

	if totalErrors > 0 {
		t.Fatalf("encountered %d errors during concurrent stress execution", totalErrors)
	}

	// Final check on record count
	finalList := store.List()
	expectedMin := len(sharedIDs) + int(totalSaves)
	if len(finalList) != expectedMin {
		t.Fatalf("expected exactly %d records, found %d", expectedMin, len(finalList))
	}
}

// TestAdversarial_DecisionStore_TTLExpirationUnderLoad tests TTL expiration during heavy concurrent polling.
func TestAdversarial_DecisionStore_TTLExpirationUnderLoad(t *testing.T) {
	store := NewMemoryDecisionStore()
	numExpiring := 100

	shortTTL := 25 * time.Millisecond
	for i := 0; i < numExpiring; i++ {
		id := fmt.Sprintf("expiring-rec-%03d", i)
		_ = store.Save(&DecisionRecord{
			DecisionID: id,
			Status:     StatusPending,
			ExpiresAt:  time.Now().UTC().Add(shortTTL),
		})
	}

	// 50 concurrent readers polling the expiring records continuously for 60ms
	numPollers := 50
	var wg sync.WaitGroup
	wg.Add(numPollers)

	stopPollers := make(chan struct{})

	for p := 0; p < numPollers; p++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopPollers:
					return
				default:
					idx := rand.Intn(numExpiring)
					id := fmt.Sprintf("expiring-rec-%03d", idx)
					rec, err := store.Get(id)
					if err != nil {
						t.Errorf("failed to get %s: %v", id, err)
					}
					if rec != nil {
						// State should only ever be PENDING or EXPIRED
						if rec.Status != StatusPending && rec.Status != StatusExpired {
							t.Errorf("unexpected status %s for expiring record", rec.Status)
						}
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Wait past expiration
	time.Sleep(50 * time.Millisecond)
	close(stopPollers)
	wg.Wait()

	// Now ALL 100 records MUST report StatusExpired
	for i := 0; i < numExpiring; i++ {
		id := fmt.Sprintf("expiring-rec-%03d", i)
		rec, err := store.Get(id)
		if err != nil {
			t.Fatalf("failed to retrieve %s: %v", id, err)
		}
		if rec.Status != StatusExpired {
			t.Fatalf("record %s was expected to be EXPIRED, got %s (ExpiresAt: %v, Now: %v)",
				id, rec.Status, rec.ExpiresAt, time.Now().UTC())
		}
	}

	// Also verify List() reports StatusExpired for all of them
	allRecs := store.List()
	for _, r := range allRecs {
		if r.Status != StatusExpired {
			t.Fatalf("record %s in List() should be EXPIRED, got %s", r.DecisionID, r.Status)
		}
	}
}

// TestAdversarial_DecisionStore_EdgeCases tests invalid inputs and boundary conditions.
func TestAdversarial_DecisionStore_EdgeCases(t *testing.T) {
	store := NewMemoryDecisionStore()

	// 1. Nil record save
	if err := store.Save(nil); err == nil {
		t.Errorf("expected error when saving nil record, got nil")
	}

	// 2. Empty DecisionID save
	if err := store.Save(&DecisionRecord{}); err == nil {
		t.Errorf("expected error when saving empty DecisionID, got nil")
	}

	// 3. Query non-existent ID
	if _, err := store.Get("non-existent-uuid"); err != ErrDecisionNotFound {
		t.Errorf("expected ErrDecisionNotFound, got %v", err)
	}

	// 4. Update non-existent ID
	if err := store.UpdateStatus("non-existent-uuid", StatusApproved); err != ErrDecisionNotFound {
		t.Errorf("expected ErrDecisionNotFound on update, got %v", err)
	}
}
