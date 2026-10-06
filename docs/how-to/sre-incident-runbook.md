# How to Handle Incidents and Operational Emergencies (SRE Runbook)

This guide provides step-by-step diagnostic and remediation procedures for Site Reliability Engineers (SREs) and DevOps responders managing the **AI Evidence & Accountability Platform**.

---

## Prerequisites & Incident Triage Kit

Before responding to active alerts, ensure you have:
* Administrative shell access to the host or Kubernetes cluster.
* Docker CLI access to inspect container logs and networks.
* `curl`, `jq`, and the standalone `ai-evidence-cli` installed.
* Target service port matrix:
  * Gateway: `http://localhost:8081`
  * Approval: `http://localhost:8082`
  * Ledger Worker: `http://localhost:8083`
  * immudb: `http://localhost:3324` / `3322`

### Global Rapid Health Assessment Command

Run this one-liner to assess all 5 components in under 5 seconds:

```bash
for port in 8081 8082 8083; do
  echo -n "Port $port: "
  curl -s -o /dev/null -w "%{http_code}\n" --max-time 2 http://localhost:$port/health
done
```
* **Expected Result**: Three consecutive `200` codes. Any `503` or timeout indicates an active incident.

---

## Scenario 1: immudb Downtime & DiskWAL Accumulation

### 1. Alert Symptom & Impact
* **Symptoms**:
  * Ledger health endpoint `GET :8083/health` reports `"immudb_status": "DISCONNECTED"`.
  * Container logs display: `[LEDGER-WORKER] immudb unavailable, persisting batch to DiskWAL`.
* **Impact**: Ingestion continues safely without packet loss due to DiskWAL buffering, but cryptographic state commits are postponed. If disk storage fills completely, the worker will drop new events.

### 2. Diagnosis Steps
```bash
# 1. Check container lifecycle
docker ps -a --filter "name=immudb"

# 2. Check immudb process logs for crash reasons (OOM, lock corruption)
docker logs --tail 50 immudb

# 3. Check WAL disk volume usage
docker exec -it ledger-worker ls -lh /var/lib/ledger/wal
```

### 3. Remediation & Recovery
```bash
# Step 1: Restart immudb container
docker compose restart immudb

# Step 2: Confirm immudb is healthy and listening on port 3324
docker exec -it immudb immuadmin status

# Step 3: Trigger automatic WAL replay and verify recovery
docker logs --tail 20 ledger-worker | grep -i "replayed"

# Step 4: Verify ledger metrics show zero uncommitted backlog
curl -s http://localhost:8083/api/v1/ledger/stats | jq '.worker.wal_replayed'
```

---

## Scenario 2: Ring-Buffer Saturation (> 80% High Watermark)

### 1. Alert Symptom & Impact
* **Symptoms**:
  * Prometheus alert `LedgerQueueHighWatermark` fires (`current_length > 40000` out of 50,000).
  * Ingestion requests to `:8081` or `:8083` intermittently return `HTTP 503 Queue saturated`.
* **Impact**: Potential dropped audit telemetry if the client uses `DropNewest` policy.

### 2. Diagnosis Steps
```bash
# Check queue capacity and drop counters
curl -s http://localhost:8083/api/v1/ledger/stats | jq '.queue'
```
* If `current_length` is climbing and `batches_flushed` is flat: The batch writer is blocked on disk I/O or database write locks.

### 3. Remediation & Recovery
1. **Force an immediate synchronous batch flush**:
   ```bash
   curl -X POST http://localhost:8083/api/v1/ledger/flush
   ```
2. **Tune batch and flush intervals dynamically** in `.env`:
   ```ini
   # Increase batch size to process more events per immudb transaction
   LEDGER_BATCH_SIZE=250
   # Reduce flush interval to flush smaller batches more frequently
   LEDGER_FLUSH_INTERVAL_MS=20
   ```
3. **Restart the Ledger Worker**:
   ```bash
   docker compose up -d --no-deps ledger-worker
   ```

---

## Scenario 3: Gateway 403 Forbidden Storm (Shadow AI Spike)

### 1. Alert Symptom & Impact
* **Symptoms**:
  * Influx of HTTP 403 responses on `POST :8081/v1/chat/completions`.
  * Gateway logs output: `[GATEWAY] Blocked unregistered system_id: <system-name>`.
* **Impact**: Legitimate AI agents or business services are blocked from calling upstream LLMs.

### 2. Diagnosis Steps
```bash
# Filter recent rejection logs from Gateway
docker logs --tail 100 gateway | grep "Blocked unregistered"
```

### 3. Remediation & Whitelisting
1. **Verify if the caller is an authorized enterprise system**:
   Confirm system identity with the application engineering lead.
2. **Update the system registry**:
   Edit `services/gateway/config/registry.json` and append the new system record:
   ```json
   {
     "system_id": "customer-onboarding-agent",
     "owner": "retail-banking-team",
     "risk_tier": "TIER_2_MODERATE",
     "pii_redaction_enabled": true,
     "allowed_models": ["gpt-4o", "gpt-4o-mini"]
   }
   ```
3. **Trigger Gateway Configuration Reload**:
   ```bash
   docker exec -it gateway kill -HUP 1
   # Or restart the gateway container
   docker compose restart gateway
   ```

---

## Scenario 4: Stalled 4-Eyes Approvals & Reviewer Deadlocks

### 1. Alert Symptom & Impact
* **Symptoms**:
  * AI requests awaiting 4-eyes approval remain stuck in `UNDER_REVIEW` indefinitely.
  * Reviewers report: `"Approval is locked by another reviewer"`.
* **Impact**: High-stakes loan or transaction approvals are blocked; client applications poll and encounter timeouts.

### 2. Diagnosis Steps
```bash
# List all pending and locked approval items
curl -s http://localhost:8082/api/v1/approvals/pending | jq .
```
* Items where `status == "UNDER_REVIEW"` and `last_heartbeat` is older than 60 seconds indicate an abandoned session.

### 3. Remediation & Lock Release
1. The platform automatically expires abandoned review locks after **90 seconds** of missing heartbeats.
2. To forcefully reset a deadlocked item back to `PENDING`:
   ```bash
   # Reset item status via administrative override
   curl -X POST http://localhost:8082/api/v1/approvals/appv-77a1c8f/reset-lock \
     -H "Authorization: Bearer $ADMIN_SECRET_TOKEN"
   ```
3. Verify the item appears again in the pending review queue.

---

## Scenario 5: Cryptographic Evidence Pack Verification Failure

### 1. Alert Symptom & Impact
* **Symptoms**:
  * Forensic validation command returns non-zero:
    ```bash
    ai-evidence-cli verify evidence_pack.zip
    # Output: FAILED: Merkle root mismatch (Exit Code 1)
    ```
* **Impact**: **P0 High Severity Security Incident**. Indicates either data tampering, bit rot, or an incomplete export archive.

### 2. Forensic Triage Checklist

```
[ ] Step 1: Quarantine the suspect evidence pack archive.
[ ] Step 2: Compute SHA-256 digest of the archive:
            sha256sum evidence_pack.zip
[ ] Step 3: Inspect archive metadata without executing full verification:
            ai-evidence-cli inspect evidence_pack.zip
[ ] Step 4: Extract and compare events.jsonl against immudb raw records:
            curl -s http://localhost:8083/api/v1/ledger/events/<event_id>
[ ] Step 5: Validate TSA timestamp validity and certificate revocation:
            openssl ts -verify -in rfc3161.tsr -data root_hash.bin -CAfile ca_chain.pem
```

### 3. Root Cause Categorization

| CLI Exit Code | Likely Root Cause | Immediate Action |
|:---:|:---|:---|
| **1 (INVALID_MERKLE)** | Single byte in `events.jsonl` was modified or line order changed. | Re-export pack directly from immudb. Compare line-by-line diff. |
| **2 (INVALID_SIGNATURE)** | Public key mismatch or corrupted signature file. | Verify public key certificate in `manifest.json`. Check expiration date. |
| **3 (MALFORMED_PACK)** | Incomplete zip download or interrupted export stream. | Re-download archive. Verify zip integrity with `unzip -t`. |
| **5 (POLICY_VIOLATION)** | Proposer self-approved or review completed before Dwell Time. | Escalate to Internal Audit and Compliance Officer immediately. |

---

## Emergency Escalation Matrix

| Severity Level | Definition | First Responder | Escalation Target | SLA |
|:---|:---|:---|:---|:---|
| **SEV-1 (Critical)** | Zero events being ingested; immudb and DiskWAL full; all AI inference failing. | On-call SRE | Platform Tech Lead & SRE Manager | $< 15\text{ mins}$ |
| **SEV-2 (High)** | Cryptographic verification failure; 4-Eyes approval service offline. | Security Incident Responder | Chief Information Security Officer (CISO) | $< 30\text{ mins}$ |
| **SEV-3 (Medium)** | Queue backlog $> 50\%$; elevated PII scan latency; non-blocking retries active. | DevOps Engineer | Backend Platform Team | $< 2\text{ hours}$ |
| **SEV-4 (Low)** | Minor metrics scrape failure; documentation inaccuracy; single unregistered system. | Support Engineer | System Administrator | Next business day |

---
*Maintained by Site Reliability Engineering & Platform Security Operations.*
