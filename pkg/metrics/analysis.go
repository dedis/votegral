package metrics

import (
	"gonum.org/v1/gonum/stat"
	"sort"
	"time"
)

// StatSummary holds final statistical results for a single set of measurements (e.g., for WallClocks).
type StatSummary struct {
	Count int
	Mean  time.Duration
	P50   time.Duration // Median
	P95   time.Duration
	Min   time.Duration
	Max   time.Duration
}

// TimeTotalsStats holds a complete StatSummary for each time type.
type TimeTotalsStats struct {
	WallClock StatSummary
	User      StatSummary
	System    StatSummary
}

// ComponentResult holds all statistical summaries for a single conceptual component.
type ComponentResult struct {
	ConceptualName string
	// Key is the derived metric type (e.g., "WallClock", "Logic", "HardwareRead")
	Summaries map[string]TimeTotalsStats
}

// AnalysisResult is the final output of the analyzer.
type AnalysisResult struct {
	Components map[string]ComponentResult
	Recorders  []*Recorder // For reference only in writing the raw output to file.
}

// Analyzer processes recorders and produces a final analysis.
type Analyzer struct {
	recorders []*Recorder
}

// NewAnalyzer creates a new analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Add collects a recorder from a single simulation run.
func (a *Analyzer) Add(recorder *Recorder) {
	a.recorders = append(a.recorders, recorder)
}

// TimeTotalsSlices holds raw timing data slices for all three time types.
type TimeTotalsSlices struct {
	WallClocks  []time.Duration
	UserTimes   []time.Duration
	SystemTimes []time.Duration
}

// intermediateData now uses TimeTotalsSlices to group data for each derived metric.
type intermediateData struct {
	// Key is the derived metric name (e.g., "WallClock", "Logic", "HardwareRead")
	metrics map[string]*TimeTotalsSlices
}

// newIntermediateData creates an empty container for intermediate data.
func newIntermediateData() *intermediateData {
	return &intermediateData{
		metrics: make(map[string]*TimeTotalsSlices),
	}
}

// Analyze is the main processing method that orchestrates the entire analysis.
func (a *Analyzer) Analyze() AnalysisResult {
	// name's key is the conceptual name (e.g., "CheckIn")
	name := make(map[string]*intermediateData)

	for _, rec := range a.recorders {
		for _, root := range rec.RootMeasurements() {
			a.processNode(root, name)
		}
	}

	finalResult := AnalysisResult{
		Components: make(map[string]ComponentResult),
		Recorders:  a.recorders,
	}
	for name, data := range name {
		compResult := ComponentResult{
			ConceptualName: name,
			Summaries:      make(map[string]TimeTotalsStats),
		}

		for derivedName, slices := range data.metrics {
			compResult.Summaries[derivedName] = calculateAllStats(slices)
		}
		finalResult.Components[name] = compResult
	}

	return finalResult
}

// processNode is a recursive helper that traverses the tree, calculates derived metrics, and populates tempData.
func (a *Analyzer) processNode(m *Measurement, tempData map[string]*intermediateData) map[MeasurementType]TimeTotals {
	descendantTotals := make(map[MeasurementType]TimeTotals)
	for _, child := range m.Children {
		childContribution := a.processNode(child, tempData)
		for mType, totals := range childContribution {
			current := descendantTotals[mType]
			current.WallClock += totals.WallClock
			current.UserTime += totals.UserTime
			current.SystemTime += totals.SystemTime
			descendantTotals[mType] = current
		}
	}

	// Only create top-level report entries for MLogic components.
	if m.Type == MLogic {
		data, ok := tempData[m.ConceptualName]
		if !ok {
			data = newIntermediateData()
			tempData[m.ConceptualName] = data
		}

		// --- 1. Handle the "WallClock" (Inclusive) metric ---
		wallClockSlices, ok := data.metrics["WallClock"]
		if !ok {
			wallClockSlices = &TimeTotalsSlices{}
			data.metrics["WallClock"] = wallClockSlices
		}
		wallClockSlices.WallClocks = append(wallClockSlices.WallClocks, m.Inclusive.WallClock)
		wallClockSlices.UserTimes = append(wallClockSlices.UserTimes, m.Inclusive.UserTime)
		wallClockSlices.SystemTimes = append(wallClockSlices.SystemTimes, m.Inclusive.SystemTime)

		// --- 2. Handle the "Logic" and other derived metrics ---
		var totalNonLogic TimeTotals
		var nonLogicByType = make(map[MeasurementType]TimeTotals)

		for mType, totals := range descendantTotals {
			if mType != MLogic {
				totalNonLogic.WallClock += totals.WallClock
				totalNonLogic.UserTime += totals.UserTime
				totalNonLogic.SystemTime += totals.SystemTime
			}
			if totals.WallClock > 0 || totals.UserTime > 0 || totals.SystemTime > 0 {
				current := nonLogicByType[mType]
				current.WallClock += totals.WallClock
				current.UserTime += totals.UserTime
				current.SystemTime += totals.SystemTime
				nonLogicByType[mType] = current
			}
		}

		logicSlices, ok := data.metrics["Logic"]
		if !ok {
			logicSlices = &TimeTotalsSlices{}
			data.metrics["Logic"] = logicSlices
		}
		logicSlices.WallClocks = append(logicSlices.WallClocks, maxDuration(0, m.Inclusive.WallClock-totalNonLogic.WallClock))
		logicSlices.UserTimes = append(logicSlices.UserTimes, maxDuration(0, m.Inclusive.UserTime-totalNonLogic.UserTime))
		logicSlices.SystemTimes = append(logicSlices.SystemTimes, maxDuration(0, m.Inclusive.SystemTime-totalNonLogic.SystemTime))

		for mType, totals := range nonLogicByType {
			// We don't want to create a derived metric for Logic itself
			if mType == MLogic {
				continue
			}
			derivedSlices, ok := data.metrics[mType.String()]
			if !ok {
				derivedSlices = &TimeTotalsSlices{}
				data.metrics[mType.String()] = derivedSlices
			}
			derivedSlices.WallClocks = append(derivedSlices.WallClocks, totals.WallClock)
			derivedSlices.UserTimes = append(derivedSlices.UserTimes, totals.UserTime)
			derivedSlices.SystemTimes = append(derivedSlices.SystemTimes, totals.SystemTime)
		}
	}

	// Return the total contribution of the subtree rooted at m to its parent.
	totalContribution := make(map[MeasurementType]TimeTotals)
	for mType, totals := range descendantTotals {
		totalContribution[mType] = totals
	}
	thisNodeTotals := totalContribution[m.Type]
	thisNodeTotals.WallClock += m.Inclusive.WallClock
	thisNodeTotals.UserTime += m.Inclusive.UserTime
	thisNodeTotals.SystemTime += m.Inclusive.SystemTime
	totalContribution[m.Type] = thisNodeTotals

	return totalContribution
}

// calculateAllStats creates a full TimeTotalsStats struct from raw data slices.
func calculateAllStats(slices *TimeTotalsSlices) TimeTotalsStats {
	return TimeTotalsStats{
		WallClock: calculateStats(slices.WallClocks),
		User:      calculateStats(slices.UserTimes),
		System:    calculateStats(slices.SystemTimes),
	}
}

// calculateStats is a private helper to compute summary stats from a slice of durations.
func calculateStats(durations []time.Duration) StatSummary {
	if len(durations) == 0 {
		return StatSummary{}
	}

	floats := make([]float64, len(durations))
	for i, v := range durations {
		floats[i] = float64(v.Microseconds())
	}
	sort.Float64s(floats)

	var mmin, mmax time.Duration
	if len(durations) > 0 {
		mmin, mmax = durations[0], durations[0]
		for _, v := range durations {
			if v < mmin {
				mmin = v
			}
			if v > mmax {
				mmax = v
			}
		}
	}

	return StatSummary{
		Count: len(durations),
		Mean:  time.Duration(stat.Mean(floats, nil)) * time.Microsecond,
		P50:   time.Duration(stat.Quantile(0.5, stat.Empirical, floats, nil)) * time.Microsecond,
		P95:   time.Duration(stat.Quantile(0.95, stat.Empirical, floats, nil)) * time.Microsecond,
		Min:   mmin,
		Max:   mmax,
	}
}

// maxDuration helper to prevent negative times.
func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
