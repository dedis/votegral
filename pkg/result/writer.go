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
)

// Writer is responsible for creating and writing result files.
type Writer struct {
	resultsPath string
	system      config.SystemType
	hwName      string
	runs        uint64
	voters      uint64
}

// NewWriter creates a new writer for result files.
func NewWriter(resultsPath string, system config.SystemType, hwName string, runs uint64, voters uint64) *Writer {
	return &Writer{
		resultsPath: resultsPath,
		system:      system,
		hwName:      hwName,
		runs:        runs,
		voters:      voters,
	}
}

// WriteAllResults writes the analysis results to files, including statistical and raw debug data, in the specified directory.
func (w *Writer) WriteAllResults(result metrics.AnalysisResult) error {
	if err := os.MkdirAll(w.resultsPath, 0755); err != nil {
		return fmt.Errorf("could not create results directory %s: %w", w.resultsPath, err)
	}

	if err := w.writeStatResults(result); err != nil {
		return fmt.Errorf("failed to write statistical results: %w", err)
	}
	if err := w.writeRawResults(result.Recorders); err != nil {
		return fmt.Errorf("failed to write raw debug results: %w", err)
	}
	return nil
}

// generateFilename creates a standardized filename for a result file.
func (w *Writer) generateFilename(fileType string) string {
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	base := fmt.Sprintf("%s_S%s_C%s_V%d_R%d_T%s.csv", fileType, w.system, w.hwName, w.voters, w.runs, timestamp)
	return filepath.Join(w.resultsPath, base)
}

// writeStatResults writes statistical analysis results into a CSV file for each component and derived metric.
func (w *Writer) writeStatResults(result metrics.AnalysisResult) error {
	filePath := w.generateFilename("STATS")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create stats file %s: %w", filePath, err)
	}
	defer file.Close()

	csvWriter := csv.NewWriter(file)
	defer csvWriter.Flush()

	header := []string{"Component", "DerivedMetric", "TimeType", "Count", "Mean_us", "Median_us", "Min_us", "Max_us", "P95_us"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	components := make([]string, 0, len(result.Components))
	for k := range result.Components {
		components = append(components, k)
	}
	sort.Strings(components)

	for _, compName := range components {
		compResult := result.Components[compName]

		derivedMetrics := make([]string, 0, len(compResult.Summaries))
		for k := range compResult.Summaries {
			derivedMetrics = append(derivedMetrics, k)
		}
		sort.Strings(derivedMetrics)

		for _, derivedName := range derivedMetrics {
			summaries := compResult.Summaries[derivedName]

			// Write a block of rows for each derived metric: one for WallClock, one for User, one for System.
			if err := writeStatsRow(csvWriter, compName, derivedName, "WallClock", summaries.WallClock); err != nil {
				return err
			}
			if err := writeStatsRow(csvWriter, compName, derivedName, "UserTime", summaries.User); err != nil {
				return err
			}
			if err := writeStatsRow(csvWriter, compName, derivedName, "SystemTime", summaries.System); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Statistical results written to %s\n", filePath)
	return nil
}

// writeStatsRow writes a single row of statistical summary data to the provided CSV writer.
func writeStatsRow(writer *csv.Writer, component, derivedMetric, timeType string, summary metrics.StatSummary) error {
	if summary.Count == 0 {
		return nil
	}
	row := []string{
		component,
		derivedMetric,
		timeType,
		strconv.Itoa(summary.Count),
		strconv.FormatInt(summary.Mean.Microseconds(), 10),
		strconv.FormatInt(summary.P50.Microseconds(), 10),
		strconv.FormatInt(summary.Min.Microseconds(), 10),
		strconv.FormatInt(summary.Max.Microseconds(), 10),
		strconv.FormatInt(summary.P95.Microseconds(), 10),
	}
	return writer.Write(row)
}

// writeRawResults dumps every single measurement from every run
func (w *Writer) writeRawResults(recorders []*metrics.Recorder) error {
	filePath := w.generateFilename("RAW")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create raw debug results file %s: %w", filePath, err)
	}
	defer file.Close()

	csvWriter := csv.NewWriter(file)
	defer csvWriter.Flush()

	header := []string{"RunIndex", "UniqueName", "ConceptualName", "Depth", "Type", "InclusiveWall_us", "InclusiveUser_us", "InclusiveSys_us"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	for i, recorder := range recorders {
		allMeasurements := make([]*metrics.Measurement, 0)
		var collectAll func(m *metrics.Measurement)
		collectAll = func(m *metrics.Measurement) {
			allMeasurements = append(allMeasurements, m)
			for _, child := range m.Children {
				collectAll(child)
			}
		}
		for _, root := range recorder.RootMeasurements() {
			collectAll(root)
		}

		sort.Slice(allMeasurements, func(i, j int) bool {
			return allMeasurements[i].UniqueName < allMeasurements[j].UniqueName
		})

		for _, m := range allMeasurements {
			row := []string{
				strconv.Itoa(i),
				m.UniqueName,
				m.ConceptualName,
				strconv.Itoa(m.Depth),
				m.Type.String(),
				strconv.FormatInt(m.Inclusive.WallClock.Microseconds(), 10),
				strconv.FormatInt(m.Inclusive.UserTime.Microseconds(), 10),
				strconv.FormatInt(m.Inclusive.SystemTime.Microseconds(), 10),
			}
			if err := csvWriter.Write(row); err != nil {
				return err
			}
		}
	}

	fmt.Printf("Raw debug results written to %s\n", filePath)
	return nil
}
