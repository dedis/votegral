package metrics

import (
	"fmt"
	"syscall"
	"time"
	"votegral/pkg/log"
)

// Measurement captures a single performance data point for one operation.
type Measurement struct {
	WallClock  time.Duration
	UserTime   time.Duration
	SystemTime time.Duration
}

// AggregatedMetrics holds the collected data for a single metric across all runs.
// This is the structure that will be written to the final CSV files.
type AggregatedMetrics struct {
	Component   string
	WallClocks  []time.Duration
	UserTimes   []time.Duration
	SystemTimes []time.Duration
}

// timer captures the state at the beginning of a measurement. It is an
// internal helper struct for the Recorder.
type timer struct {
	name           string
	startTime      time.Time
	startRUsage    syscall.Rusage
	startRChildren syscall.Rusage
}

// Recorder is an object that records and processes performance metrics for a
// single simulation run.
type Recorder struct {
	printDebug bool
	metrics    map[string]*Measurement
	timers     map[string]*timer
}

// NewRecorder creates a new, empty recorder for a single simulation run.
func NewRecorder(printDebug bool) *Recorder {
	return &Recorder{
		printDebug: printDebug,
		metrics:    make(map[string]*Measurement),
		timers:     make(map[string]*timer),
	}
}

// Record wraps a function call, measuring its performance.
// This is the primary method for recording metrics.
func (r *Recorder) Record(name string, f func() error) error {
	t, err := r.start(name)
	if err != nil {
		return fmt.Errorf("could not start timer for '%s': %w", name, err)
	}

	opErr := f()

	// Always stop the timer, even if the operation failed.
	if err := r.stop(t); err != nil {
		return fmt.Errorf("could not stop timer for '%s': %w", name, err)
	}

	return opErr
}

// start captures the initial wall-clock time and resource usage.
func (r *Recorder) start(name string) (*timer, error) {
	if _, exists := r.timers[name]; exists {
		return nil, fmt.Errorf("timer '%s' already started", name)
	}

	t := &timer{name: name}
	var err error

	t.startRUsage, err = getRUsage(syscall.RUSAGE_SELF)
	if err != nil {
		return nil, err
	}
	t.startRChildren, err = getRUsage(syscall.RUSAGE_CHILDREN)
	if err != nil {
		return nil, err
	}
	// Record wall-clock time last to minimize measurement overhead.
	t.startTime = time.Now()

	r.timers[name] = t
	return t, nil
}

// stop captures the final time and resource usage, calculates the deltas,
// and stores them as a Measurement.
func (r *Recorder) stop(t *timer) error {
	// Record wall-clock time first.
	endTime := time.Now()

	endRUsage, err := getRUsage(syscall.RUSAGE_SELF)
	if err != nil {
		return err
	}
	endRChildren, err := getRUsage(syscall.RUSAGE_CHILDREN)
	if err != nil {
		return err
	}

	delete(r.timers, t.name)

	measurement := &Measurement{
		WallClock:  endTime.Sub(t.startTime),
		UserTime:   rtimeDifference(t.startRUsage.Utime, endRUsage.Utime) + rtimeDifference(t.startRChildren.Utime, endRChildren.Utime),
		SystemTime: rtimeDifference(t.startRUsage.Stime, endRUsage.Stime) + rtimeDifference(t.startRChildren.Stime, endRChildren.Stime),
	}

	r.metrics[t.name] = measurement

	if r.printDebug {
		log.Info("[METRIC: %s] Wall: %s, User: %s, Sys: %s\n",
			t.name, measurement.WallClock, measurement.UserTime, measurement.SystemTime)
	}

	return nil
}

// Finalize calculates derived metrics after all primary measurements are done.
// Specifically, it calculates the "Crypto & Logic" time by subtracting all
// specified sub-component times from a total time.
func (r *Recorder) Finalize(totalName string, subNames []string) {
	total, ok := r.metrics[totalName]
	if !ok {
		log.Info("Warning: Cannot finalize metrics, total component '%s' not found.", totalName)
		return
	}

	var subWall, subUser, subSys time.Duration
	for _, name := range subNames {
		sub, ok := r.metrics[name]
		if !ok {
			//log.Warn("Warning: Sub-component '%s' not found for final calculation.", name)
			continue
		}
		subWall += sub.WallClock
		subUser += sub.UserTime
		subSys += sub.SystemTime
	}

	logicWall := total.WallClock - subWall
	logicUser := total.UserTime - subUser
	logicSys := total.SystemTime - subSys

	// Ensure we don't record negative durations if there's measurement noise.
	if logicWall < 0 {
		logicWall = 0
	}
	if logicUser < 0 {
		logicUser = 0
	}
	if logicSys < 0 {
		logicSys = 0
	}

	logicMetricName := totalName + "_Logic"
	r.metrics[logicMetricName] = &Measurement{
		WallClock:  logicWall,
		UserTime:   logicUser,
		SystemTime: logicSys,
	}

	if r.printDebug {
		log.Info("[METRIC: %s] Wall: %s, User: %s, Sys: %s\n",
			logicMetricName, logicWall, logicUser, logicSys)
	}
}

func (r *Recorder) GetMetric(metric string) *Measurement {
	return r.metrics[metric]
}

// --- Aggregator ---

// Aggregator collects metrics from multiple Recorders.
type Aggregator struct {
	allMetrics map[string]*AggregatedMetrics
}

// NewAggregator creates an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{allMetrics: make(map[string]*AggregatedMetrics)}
}

// Add incorporates the metrics from a single run's Recorder into the aggregate totals.
func (a *Aggregator) Add(recorder *Recorder) {
	for name, m := range recorder.metrics {
		if _, ok := a.allMetrics[name]; !ok {
			a.allMetrics[name] = &AggregatedMetrics{Component: name}
		}
		a.allMetrics[name].WallClocks = append(a.allMetrics[name].WallClocks, m.WallClock)
		a.allMetrics[name].UserTimes = append(a.allMetrics[name].UserTimes, m.UserTime)
		a.allMetrics[name].SystemTimes = append(a.allMetrics[name].SystemTimes, m.SystemTime)
	}
}

// GetAggregatedMetrics returns the final map of all collected metrics.
func (a *Aggregator) GetAggregatedMetrics() map[string]*AggregatedMetrics {
	return a.allMetrics
}

// --- OS Utilities ---

// getRUsage is a simple wrapper around syscall.Getrusage.
func getRUsage(who int) (syscall.Rusage, error) {
	var rusage syscall.Rusage
	err := syscall.Getrusage(who, &rusage)
	return rusage, err
}

// rtimeDifference calculates the time.Duration between two syscall.Timeval structs.
func rtimeDifference(start, end syscall.Timeval) time.Duration {
	startDuration := time.Duration(start.Sec)*time.Second + time.Duration(start.Usec)*time.Microsecond
	endDuration := time.Duration(end.Sec)*time.Second + time.Duration(end.Usec)*time.Microsecond
	return endDuration - startDuration
}
