package dualmode

import "strings"

const (
	ModeAuditOnly = "AUDIT_ONLY"
	ModeIntercept = "INTERCEPT_AND_APPROVE"

	HeaderRequireApproval = "X-Require-Approval"
)

// Evaluate determines whether a request runs in Audit-Only or Intercept & Approve mode.
// Any affirmative trigger (header, body flag, or registry policy) forces Intercept & Approve mode.
func Evaluate(headerVal string, bodyFlag bool, registryPolicyFlag bool) string {
	h := strings.TrimSpace(strings.ToLower(headerVal))
	if h == "true" || h == "1" || h == "yes" {
		return ModeIntercept
	}
	if bodyFlag {
		return ModeIntercept
	}
	if registryPolicyFlag {
		return ModeIntercept
	}
	return ModeAuditOnly
}
