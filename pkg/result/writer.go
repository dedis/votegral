package result

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
	"votegral/pkg/config"
	"votegral/pkg/metrics"

	"gonum.org/v1/gonum/stat"
)

// Writer is responsible for creating and writing result files.
type Writer struct {
	resultsPath string
	system      config.SystemType
	hwName      string
	runs        uint64
}

// NewWriter creates a new writer for result files.
func NewWriter(resultsPath string, system config.SystemType, hwName string, runs uint64) *Writer {
	return &Writer{
		resultsPath: resultsPath,
		system:      system,
		hwName:      hwName,
		runs:        runs,
	}
}

// WriteAllResults is the main entry point that generates and writes all result files.
func (w *Writer) WriteAllResults(metrics map[string]*metrics.AggregatedMetrics) error {
	// Create the results directory if it doesn't exist.
	if err := os.MkdirAll(w.resultsPath, 0755); err != nil {
		return fmt.Errorf("could not create results directory %s: %w", w.resultsPath, err)
	}

	if err := w.writeRawResults(metrics); err != nil {
		return fmt.Errorf("failed to write raw results: %w", err)
	}
	if err := w.writeStatResults(metrics); err != nil {
		return fmt.Errorf("failed to write statistical results: %w", err)
	}
	return nil
}

// generateFilename creates a standardized filename for a result file.
// Example: RAW_S_Mac_C_Disk_R_100_T_2025-01-02-15-04-05.csv
func (w *Writer) generateFilename(fileType string) string {
	timestamp := time.Now().Format("2025-01-02-15-04-05")
	base := fmt.Sprintf("%s_S%s_C%s_R%d_T%s.csv",
		fileType,
		w.system,
		w.hwName,
		w.runs,
		timestamp,
	)
	return filepath.Join(w.resultsPath, base)
}

// writeRawResults saves the raw execution time for every operation in every run.
func (w *Writer) writeRawResults(allMetrics map[string]*metrics.AggregatedMetrics) error {
	filePath := w.generateFilename("RAW")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create raw results file %s: %w", filePath, err)
	}
	defer file.Close()

	csvWriter := csv.NewWriter(file)
	defer csvWriter.Flush()

	header := []string{"Component", "MetricType", "ExecutionTime_us"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header to %s: %w", filePath, err)
	}

	components := getSortedKeys(allMetrics)

	for _, componentName := range components {
		aggMetrics := allMetrics[componentName]

		// Write Wall Clock times
		for _, t := range aggMetrics.WallClocks {
			row := []string{componentName, "WallClock", fmt.Sprintf("%d", t.Microseconds())}
			if err := csvWriter.Write(row); err != nil {
				return fmt.Errorf("failed to write row to %s: %w", filePath, err)
			}
		}
		// Write User CPU times
		for _, t := range aggMetrics.UserTimes {
			row := []string{componentName, "UserTime", fmt.Sprintf("%d", t.Microseconds())}
			if err := csvWriter.Write(row); err != nil {
				return fmt.Errorf("failed to write row to %s: %w", filePath, err)
			}
		}
		// Write System CPU times
		for _, t := range aggMetrics.SystemTimes {
			row := []string{componentName, "SystemTime", fmt.Sprintf("%d", t.Microseconds())}
			if err := csvWriter.Write(row); err != nil {
				return fmt.Errorf("failed to write row to %s: %w", filePath, err)
			}
		}
	}
	fmt.Printf("Raw results written to %s\n", filePath)
	return nil
}

// writeStatResults calculates and saves summary statistics for each component.
func (w *Writer) writeStatResults(allMetrics map[string]*metrics.AggregatedMetrics) error {
	filePath := w.generateFilename("STATS")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create stats file %s: %w", filePath, err)
	}
	defer file.Close()

	csvWriter := csv.NewWriter(file)
	defer csvWriter.Flush()

	header := []string{"Component", "MetricType", "Mean_us", "Median_us", "Min_us", "Max_us", "P5_us", "P95_us"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header to %s: %w", filePath, err)
	}

	components := getSortedKeys(allMetrics)

	for _, componentName := range components {
		aggMetrics := allMetrics[componentName]

		// Calculate and write stats for each metric type (Wall, User, System)
		if err := writeStatsRow(csvWriter, componentName, "WallClock", aggMetrics.WallClocks); err != nil {
			return err
		}
		if err := writeStatsRow(csvWriter, componentName, "UserTime", aggMetrics.UserTimes); err != nil {
			return err
		}
		if err := writeStatsRow(csvWriter, componentName, "SystemTime", aggMetrics.SystemTimes); err != nil {
			return err
		}
	}
	fmt.Printf("Statistical results written to %s\n", filePath)
	return nil
}

// writeStatsRow calculates statistics for a set of durations and writes them to a CSV row.
func writeStatsRow(writer *csv.Writer, component, metricType string, durations []time.Duration) error {
	if len(durations) == 0 {
		return nil
	}

	floats := convertDurationsToFloats(durations)

	sort.Float64s(floats)

	mean := stat.Mean(floats, nil)
	median := stat.Quantile(0.5, stat.Empirical, floats, nil)
	p5 := stat.Quantile(0.05, stat.Empirical, floats, nil)
	p95 := stat.Quantile(0.95, stat.Empirical, floats, nil)

	min, max := minMaxDuration(durations)

	row := []string{
		component,
		metricType,
		strconv.FormatFloat(mean, 'f', -1, 64),
		strconv.FormatFloat(median, 'f', -1, 64),
		strconv.FormatInt(min.Microseconds(), 10),
		strconv.FormatInt(max.Microseconds(), 10),
		strconv.FormatFloat(p5, 'f', -1, 64),
		strconv.FormatFloat(p95, 'f', -1, 64),
	}

	if err := writer.Write(row); err != nil {
		return fmt.Errorf("failed to write stats row for %s (%s): %w", component, metricType, err)
	}
	return nil
}

// getSortedKeys extracts keys from a map and returns them sorted alphabetically.
func getSortedKeys(m map[string]*metrics.AggregatedMetrics) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// convertDurationsToFloats converts a slice of time.Duration to a slice of float64 (in microseconds).
func convertDurationsToFloats(d []time.Duration) []float64 {
	floats := make([]float64, len(d))
	for i, v := range d {
		floats[i] = float64(v.Microseconds())
	}
	return floats
}

// minMaxDuration finds the minimum and maximum duration in a slice.
func minMaxDuration(d []time.Duration) (min, max time.Duration) {
	if len(d) == 0 {
		return 0, 0
	}
	min, max = d[0], d[0]
	for _, v := range d[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}
