package mlingest

import "errors"

// ValidateMLIngestRequest validates mandatory fields for ML ingestion.
func ValidateMLIngestRequest(req *MLIngestRequest) error {
	if req == nil {
		return errors.New("request payload cannot be empty")
	}
	if req.AISystemID == "" {
		return errors.New("Missing required field: ai_system_id")
	}
	if req.Score == nil {
		return errors.New("Missing required field: score")
	}
	return nil
}
