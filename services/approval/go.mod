module ei-evidence-platform/services/approval

go 1.22

require (
	ei-evidence-platform/services/gateway v0.0.0
	ei-evidence-platform/services/ledger v0.0.0
	github.com/go-chi/chi/v5 v5.0.12
	github.com/google/uuid v1.6.0
)

replace ei-evidence-platform/services/gateway => ../gateway

replace ei-evidence-platform/services/ledger => ../ledger
