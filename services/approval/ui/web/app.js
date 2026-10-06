// State Management
let currentDecision = null;
let dwellRemainingSecs = 10;
let dwellElapsedSecs = 0;
let dwellTimerInterval = null;
let heartbeatInterval = null;
let activePersona = { id: "credit-lead-01", role: "credit_lead" };
let isTabFocused = true;
let allPendingItems = [];

// Initialization
document.addEventListener("DOMContentLoaded", () => {
    initPersonaSelector();
    initTabVisibilityTracker();
    initFilterControls();
    loadPendingQueue();
    setInterval(loadPendingQueue, 5000); // Poll pending list every 5s
});

function initPersonaSelector() {
    const select = document.getElementById("persona-select");
    const badge = document.getElementById("active-user-badge");
    if (!select) return;
    select.addEventListener("change", (e) => {
        const parts = e.target.value.split("|");
        activePersona = { id: parts[0], role: parts[1] };
        if (badge) badge.textContent = parts[1];
        if (currentDecision) {
            checkSeparationOfDuties(currentDecision);
        }
    });
}

function initTabVisibilityTracker() {
    document.addEventListener("visibilitychange", () => {
        isTabFocused = !document.hidden;
        const warning = document.getElementById("tab-focus-warning");
        if (warning) {
            if (!isTabFocused) {
                warning.classList.remove("hidden");
            } else {
                warning.classList.add("hidden");
            }
        }
    });
}

function initFilterControls() {
    const searchInput = document.getElementById("filter-search");
    const typeSelect = document.getElementById("filter-type");
    if (searchInput) {
        searchInput.addEventListener("input", applyQueueFilter);
    }
    if (typeSelect) {
        typeSelect.addEventListener("change", applyQueueFilter);
    }
}

// -----------------------------------------------------------------------------
// Pending Queue API & Rendering
// -----------------------------------------------------------------------------
async function loadPendingQueue() {
    try {
        const resp = await fetch("/api/v1/approvals/pending");
        if (!resp.ok) return;
        const data = await resp.json();
        allPendingItems = data.items || [];
        applyQueueFilter();
    } catch (err) {
        console.error("Failed to load queue:", err);
    }
}

function applyQueueFilter() {
    const searchInput = document.getElementById("filter-search");
    const typeSelect = document.getElementById("filter-type");
    const search = (searchInput ? searchInput.value : "").trim().toLowerCase();
    const type = typeSelect ? typeSelect.value : "all";

    let filtered = allPendingItems.filter(item => {
        if (type !== "all" && item.system_type && item.system_type.toLowerCase() !== type.toLowerCase()) {
            return false;
        }
        if (search) {
            const matchesId = (item.decision_id || "").toLowerCase().includes(search);
            const matchesSys = (item.ai_system_id || "").toLowerCase().includes(search);
            if (!matchesId && !matchesSys) return false;
        }
        return true;
    });

    renderQueueTable(filtered);
}

function renderQueueTable(items) {
    const tbody = document.getElementById("queue-table-body");
    const countBadge = document.getElementById("queue-count-badge");
    if (countBadge) {
        countBadge.textContent = `${items.length} chờ duyệt`;
    }

    if (!tbody) return;

    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Không có quyết định nào đang chờ.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => `
        <tr onclick="selectDecision('${item.decision_id}')" class="${currentDecision && currentDecision.decision_id === item.decision_id ? 'active-row' : ''}">
            <td><strong>${escapeHtml(item.decision_id)}</strong></td>
            <td>${escapeHtml(item.ai_system_id)}</td>
            <td><span class="badge badge-${item.risk_tier === 'CRITICAL' ? 'danger' : 'warning'}">${escapeHtml(item.risk_tier)}</span></td>
            <td><span class="badge badge-info">${item.current_approvers}/${item.required_approvers}</span></td>
            <td>${item.waiting_time_seconds}s</td>
            <td><button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); selectDecision('${item.decision_id}')">Xem</button></td>
        </tr>
    `).join("");
}

// -----------------------------------------------------------------------------
// Decision Detail & Dwell Timer
// -----------------------------------------------------------------------------
async function selectDecision(id) {
    clearInterval(dwellTimerInterval);
    clearInterval(heartbeatInterval);

    try {
        const resp = await fetch(`/api/v1/approvals/${id}`);
        if (!resp.ok) {
            showBanner("Không thể tải chi tiết quyết định: " + id, "danger");
            return;
        }
        currentDecision = await resp.json();
        renderDecisionDetail(currentDecision);
        startDwellTracking(currentDecision);
        loadPendingQueue();
    } catch (err) {
        console.error("Error fetching detail:", err);
    }
}

function renderDecisionDetail(d) {
    const emptyState = document.getElementById("empty-detail-state");
    const activeContent = document.getElementById("active-detail-content");
    if (emptyState) emptyState.classList.add("hidden");
    if (activeContent) activeContent.classList.remove("hidden");

    const idEl = document.getElementById("detail-decision-id");
    const sysEl = document.getElementById("detail-system-type");
    const riskEl = document.getElementById("detail-risk-tier");
    const statusEl = document.getElementById("detail-status");
    const metaEl = document.getElementById("detail-meta-text");

    if (idEl) idEl.textContent = d.decision_id;
    if (sysEl) sysEl.textContent = (d.system_type || "").toUpperCase();
    if (riskEl) riskEl.textContent = d.risk_tier;
    if (statusEl) statusEl.textContent = d.status;
    if (metaEl) metaEl.textContent = `Hệ thống: ${d.ai_system_id} (${d.model_version || 'v1'}) • Người tạo: ${d.creator_id}`;

    // Stepper 4-Eyes
    renderFourEyesStepper(d);

    // Inspection View Switcher
    const mlView = document.getElementById("ml-inspection-view");
    const llmView = document.getElementById("llm-inspection-view");

    if (d.system_type === "ml" && d.ml_context) {
        if (mlView) mlView.classList.remove("hidden");
        if (llmView) llmView.classList.add("hidden");
        renderMLContext(d.ml_context);
    } else if (d.system_type === "llm" && d.llm_context) {
        if (llmView) llmView.classList.remove("hidden");
        if (mlView) mlView.classList.add("hidden");
        renderLLMContext(d.llm_context);
    } else {
        if (mlView) mlView.classList.add("hidden");
        if (llmView) llmView.classList.add("hidden");
    }

    checkSeparationOfDuties(d);
}

function renderFourEyesStepper(d) {
    const s1 = document.getElementById("step-node-1");
    const s2 = document.getElementById("step-node-2");
    const sub1 = document.getElementById("step-1-sub");
    const sub2 = document.getElementById("step-2-sub");

    const history = d.approval_history || [];
    if (history.length >= 1) {
        if (s1) s1.className = "step completed";
        if (sub1) sub1.textContent = `Đã duyệt bởi: ${history[0].approver_id}`;
    } else {
        if (s1) s1.className = "step current";
        if (sub1) sub1.textContent = "Chờ bước 1";
    }

    if (history.length >= 2) {
        if (s2) s2.className = "step completed";
        if (sub2) sub2.textContent = `Đã duyệt bởi: ${history[1].approver_id}`;
    } else if (history.length === 1) {
        if (s2) s2.className = "step current";
        if (sub2) sub2.textContent = "Chờ bước 2 (Độc lập)";
    } else {
        if (s2) s2.className = "step";
        if (sub2) sub2.textContent = "Chờ bước 2";
    }
}

function checkSeparationOfDuties(d) {
    const warnBox = document.getElementById("separation-warning-box");
    const btnApprove = document.getElementById("btn-approve");
    if (warnBox) warnBox.innerHTML = "";

    // 1. Creator Self-Approval Violation Check
    if (activePersona.id === d.creator_id) {
        if (warnBox) {
            warnBox.innerHTML = `<div class="badge badge-danger text-sm" style="display:block; margin-top:0.5rem; padding:0.5rem;">
                ⚠️ BẠN LÀ NGƯỜI TẠO HỒ SƠ NÀY (${escapeHtml(d.creator_id)}). Theo quy tắc 4-Mắt, bạn KHÔNG ĐƯỢC PHÉP tự phê duyệt!
            </div>`;
        }
        if (btnApprove) {
            btnApprove.disabled = true;
            btnApprove.title = "Người tạo không thể tự duyệt (Rule CREATOR_CANNOT_APPROVE)";
        }
        return false;
    }

    // 2. Duplicate Approver Check
    const history = d.approval_history || [];
    if (history.length === 1 && history[0].approver_id === activePersona.id) {
        if (warnBox) {
            warnBox.innerHTML = `<div class="badge badge-warning text-sm" style="display:block; margin-top:0.5rem; padding:0.5rem;">
                ⚠️ BẠN ĐÃ PHÊ DUYỆT BƯỚC 1. Quy tắc 4-Mắt yêu cầu người duyệt thứ 2 độc lập!
            </div>`;
        }
        if (btnApprove) {
            btnApprove.disabled = true;
            btnApprove.title = "Cần người duyệt độc lập khác (Rule DUPLICATE_APPROVER)";
        }
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------
// ML SHAP Waterfall Chart Rendering (Pure CSS/DOM)
// -----------------------------------------------------------------------------
function renderMLContext(ml) {
    const scoreVal = document.getElementById("ml-score-val");
    const decLabel = document.getElementById("ml-decision-label");
    const amtLabel = document.getElementById("ml-amount-label");

    if (scoreVal) scoreVal.textContent = typeof ml.score === 'number' ? ml.score.toFixed(1) : ml.score;
    if (decLabel) decLabel.textContent = ml.decision || "";
    if (amtLabel && ml.amount_vnd) {
        amtLabel.textContent = `Số tiền: ${ml.amount_vnd.toLocaleString('vi-VN')} VND`;
    }

    // SHAP Chart
    const chart = document.getElementById("shap-chart");
    if (chart) {
        chart.innerHTML = "";
        if (ml.explanation && ml.explanation.top_features) {
            ml.explanation.top_features.forEach(feat => {
                const widthPct = Math.min(Math.abs(feat.importance) * 100 * 1.5, 95);
                chart.innerHTML += `
                    <div class="shap-row">
                        <div class="shap-label" title="${escapeHtml(feat.feature)}">${escapeHtml(feat.feature)}</div>
                        <div class="shap-bar-track">
                            <div class="shap-bar ${feat.direction}" style="width: ${widthPct}%;">
                                ${escapeHtml(feat.contribution)} (${escapeHtml(String(feat.value))})
                            </div>
                        </div>
                    </div>
                `;
            });
        }
    }

    // Features Table
    const fbody = document.getElementById("features-table-body");
    if (fbody) {
        fbody.innerHTML = Object.entries(ml.features || {}).map(([k, v]) => `
            <tr><td><strong>${escapeHtml(k)}</strong></td><td>${escapeHtml(typeof v === 'number' ? v.toLocaleString('vi-VN') : String(v))}</td></tr>
        `).join("");
    }
}

// -----------------------------------------------------------------------------
// LLM Prompt Diff & PII Badges
// -----------------------------------------------------------------------------
function renderLLMContext(llm) {
    // PII Badges
    const badgeList = document.getElementById("pii-badges-list");
    if (badgeList) {
        badgeList.innerHTML = (llm.pii_detected || []).map(p => `
            <span class="badge ${p === 'CCCD' ? 'badge-cccd' : p === 'PHONE' ? 'badge-phone' : 'badge-bank'}">[${escapeHtml(p)}]</span>
        `).join("");
    }

    // Diff Spans
    const diffView = document.getElementById("prompt-diff-view");
    if (diffView) {
        if (llm.prompt_diff_spans && llm.prompt_diff_spans.length > 0) {
            diffView.innerHTML = llm.prompt_diff_spans.map(span => {
                if (span.type === "pii_masked") {
                    const cls = span.tag === "[CCCD]" ? "badge-cccd" : span.tag === "[SĐT]" ? "badge-phone" : "badge-bank";
                    return `<mark class="diff-span-pii ${cls}" title="Gốc: ${escapeHtml(span.original)}">${escapeHtml(span.text)} ${escapeHtml(span.tag)}</mark>`;
                }
                return `<span>${escapeHtml(span.text)}</span>`;
            }).join("");
        } else {
            diffView.textContent = llm.masked_prompt || "";
        }
    }
}

// -----------------------------------------------------------------------------
// Dwell Tracking & Heartbeat Loop
// -----------------------------------------------------------------------------
function startDwellTracking(d) {
    const requiredSecs = (d.anti_rubberstamp && d.anti_rubberstamp.min_dwell_seconds) ? d.anti_rubberstamp.min_dwell_seconds : 10;
    dwellRemainingSecs = requiredSecs;
    dwellElapsedSecs = 0;

    const reqSecEl = document.getElementById("dwell-required-sec");
    if (reqSecEl) reqSecEl.textContent = requiredSecs;

    const timerText = document.getElementById("dwell-timer-text");
    const progressFill = document.getElementById("dwell-progress-fill");
    const btnApprove = document.getElementById("btn-approve");

    if (timerText) {
        timerText.className = "dwell-timer-display";
        timerText.textContent = `00:${dwellRemainingSecs < 10 ? '0' : ''}${dwellRemainingSecs}`;
    }
    if (progressFill) {
        progressFill.className = "progress-bar-fill";
        progressFill.style.width = "0%";
    }
    if (btnApprove) {
        btnApprove.disabled = true;
        btnApprove.title = "Vui lòng đọc hồ sơ đủ thời gian tối thiểu";
    }

    dwellTimerInterval = setInterval(() => {
        if (!isTabFocused) return; // Pause timer if tab inactive

        dwellElapsedSecs++;
        dwellRemainingSecs--;
        const pct = Math.min(((requiredSecs - dwellRemainingSecs) / requiredSecs) * 100, 100);
        if (progressFill) progressFill.style.width = `${pct}%`;

        if (dwellRemainingSecs <= 0) {
            clearInterval(dwellTimerInterval);
            if (timerText) {
                timerText.textContent = "00:00 (Đã hoàn tất)";
                timerText.classList.add("unlocked");
            }
            if (progressFill) progressFill.classList.add("unlocked");

            if (checkSeparationOfDuties(currentDecision)) {
                if (btnApprove) {
                    btnApprove.disabled = false;
                    btnApprove.title = "Nhấn để phê duyệt";
                    btnApprove.innerHTML = "✔ Phê duyệt (Approve)";
                }
            }
        } else {
            if (timerText) {
                timerText.textContent = `00:${dwellRemainingSecs < 10 ? '0' : ''}${dwellRemainingSecs}`;
            }
        }
    }, 1000);

    // Heartbeat every 2 seconds
    heartbeatInterval = setInterval(async () => {
        if (!currentDecision) return;
        try {
            await fetch(`/api/v1/approvals/${currentDecision.decision_id}/dwell`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    viewer_id: activePersona.id,
                    session_id: "web-session-active",
                    incremental_ms: 2000,
                    tab_focused: isTabFocused
                })
            });
        } catch (e) {
            console.warn("Dwell heartbeat failed:", e);
        }
    }, 2000);
}

// -----------------------------------------------------------------------------
// Decision Submission Action
// -----------------------------------------------------------------------------
async function submitDecision(action) {
    if (!currentDecision) return;

    const signerTypeSelect = document.getElementById("signer-type-select");
    const commentInput = document.getElementById("decision-comment");

    const signerType = signerTypeSelect ? signerTypeSelect.value : "internal";
    const comment = commentInput ? commentInput.value : "";

    const minDwell = (currentDecision.anti_rubberstamp && currentDecision.anti_rubberstamp.min_dwell_seconds)
        ? currentDecision.anti_rubberstamp.min_dwell_seconds
        : 10;
    const dwellSeconds = Math.max(minDwell, dwellElapsedSecs);

    // Send final dwell heartbeat flush to ensure server active session is synchronized
    try {
        await fetch(`/api/v1/approvals/${currentDecision.decision_id}/dwell`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                viewer_id: activePersona.id,
                session_id: "web-session-active",
                incremental_ms: 2000,
                tab_focused: isTabFocused
            })
        });
    } catch (e) {
        console.warn("Final dwell heartbeat flush warning:", e);
    }

    const payload = {
        approver_id: activePersona.id,
        role: activePersona.role,
        action: action,
        signer_type: signerType,
        dwell_seconds: dwellSeconds,
        session_token: "web-session-active",
        comment: comment
    };

    try {
        const resp = await fetch(`/api/v1/approvals/${currentDecision.decision_id}/decide`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const result = await resp.json();
        if (!resp.ok) {
            showBanner(`Lỗi ${result.code || resp.status}: ${result.error}`, "danger");
            return;
        }

        showBanner(result.message || "Xử lý thành công", "success");
        clearInterval(dwellTimerInterval);
        clearInterval(heartbeatInterval);
        selectDecision(currentDecision.decision_id);
    } catch (err) {
        showBanner("Lỗi kết nối khi gửi phê duyệt: " + err.message, "danger");
    }
}

function showBanner(msg, type) {
    const banner = document.getElementById("banner-container");
    if (!banner) return;
    banner.innerHTML = `<div class="badge badge-${type}" style="display:block; padding:0.75rem; margin-bottom:1rem; font-size:0.9rem;">${escapeHtml(msg)}</div>`;
    setTimeout(() => { banner.innerHTML = ""; }, 6000);
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Export functions to global scope for HTML onclick attributes
window.selectDecision = selectDecision;
window.submitDecision = submitDecision;
