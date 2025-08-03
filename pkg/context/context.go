package context

import (
	"votegral/pkg/config"
	"votegral/pkg/metrics"
)

// OperationContext holds request-scoped data for a single protocol operation.
type OperationContext struct {
	Config   *config.Config    // The simulation configuration
	Recorder *metrics.Recorder // The metrics recorder for the current simulation run.
}

// NewContext creates a new OperationContext.
func NewContext(config *config.Config, rec *metrics.Recorder) *OperationContext {
	return &OperationContext{
		Config:   config,
		Recorder: rec,
	}
}
