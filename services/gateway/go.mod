module ei-evidence-platform/services/gateway

go 1.22

require (
	ei-evidence-platform/services/ledger v0.0.0
	github.com/go-chi/chi/v5 v5.0.12 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

replace ei-evidence-platform/services/ledger => ../ledger
