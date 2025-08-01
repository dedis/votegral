package context

import (
	"votegral/pkg/config"
	"votegral/pkg/metrics"
)

// OperationContext holds request-scoped data for a single protocol operation.
// It is passed through the layers of the application, from the simulation
// entry point down to the hardware and I/O methods.
type OperationContext struct {
	Config   *config.Config    // The configuration
	Recorder *metrics.Recorder // The metrics recorder for the current simulation run.
}

// NewContext creates a new OperationContext.
func NewContext(config *config.Config, rec *metrics.Recorder) *OperationContext {
	return &OperationContext{
		Config:   config,
		Recorder: rec,
	}
}
