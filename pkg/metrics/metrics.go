package metrics

import (
	"fmt"
	"io"
	"syscall"
	"time"
)

// MeasurementType defines the measurement observed.
type MeasurementType uint

const (
	MLogic MeasurementType = iota
	MHardwareRead
	MHardwareWrite
	MDiskRead
	MDiskWrite
)

func (mt MeasurementType) String() string {
	switch mt {
	case MLogic:
		return "Logic"
	case MHardwareRead:
		return "HardwareRead"
	case MHardwareWrite:
		return "HardwareWrite"
	case MDiskRead:
		return "DiskRead"
	case MDiskWrite:
		return "DiskWrite"
	default:
		return "Unknown"
	}
}

type TimeTotals struct {
	WallClock, UserTime, SystemTime time.Duration
}

// Measurement is a node in the performance measurement tree. It is a simple data container.
type Measurement struct {
	ConceptualName  string
	UniqueName      string
	Type            MeasurementType
	Depth           int
	Inclusive       TimeTotals
	Children        []*Measurement
	childNameCounts map[string]int

	startTime      time.Time
	startRUsage    syscall.Rusage
	startRChildren syscall.Rusage
}

// Recorder builds the measurement tree for a single run.
type Recorder struct {
	allMeasurements  map[string]*Measurement // Keyed by UniqueName
	rootMeasurements []*Measurement
	activeStack      []*Measurement
}

// NewRecorder creates a new, empty recorder for a single run.
func NewRecorder() *Recorder {
	return &Recorder{
		allMeasurements:  make(map[string]*Measurement),
		activeStack:      make([]*Measurement, 0),
		rootMeasurements: make([]*Measurement, 0),
	}
}

// Record measures the execution time and system resource usage of a function, identified by a conceptual name.
// It starts a measurement, executes the provided function, and stops the measurement, capturing performance metrics.
func (r *Recorder) Record(conceptualName string, mType MeasurementType, f func() error) (err error) {
	if err = r.start(conceptualName, mType); err != nil {
		return fmt.Errorf("could not start timer for '%s': %w", conceptualName, err)
	}
	defer func() {
		stopErr := r.stop(conceptualName)
		if stopErr != nil {
			if err != nil {
				err = fmt.Errorf("op error for '%s' (%w) and stop error (%w)", conceptualName, err, stopErr)
			} else {
				err = stopErr
			}
		}
	}()
	return f()
}

// start initializes and begins a new measurement, tracking its resource usage and ensuring unique naming within its context.
func (r *Recorder) start(conceptualName string, mType MeasurementType) error {
	var parent *Measurement
	depth := 0
	childCounts := make(map[string]int)

	if len(r.activeStack) > 0 {
		parent = r.activeStack[len(r.activeStack)-1]
		depth = parent.Depth + 1
		childCounts = parent.childNameCounts
	} else {
		// This is a root-level measurement.
		tempRootCounts := make(map[string]int)
		for _, root := range r.rootMeasurements {
			tempRootCounts[root.ConceptualName]++
		}
		childCounts = tempRootCounts
	}

	count := childCounts[conceptualName]
	childCounts[conceptualName] = count + 1

	// Generate a unique name in case there are duplicates.
	uniqueName := fmt.Sprintf("%s_%d", conceptualName, count)
	if count == 0 {
		isRoot := parent == nil
		isUniqueRoot := true
		if isRoot {
			for _, root := range r.rootMeasurements {
				if root.ConceptualName == conceptualName {
					isUniqueRoot = false
					break
				}
			}
		}
		if isUniqueRoot {
			uniqueName = conceptualName
		}
	}

	m := &Measurement{
		ConceptualName:  conceptualName,
		UniqueName:      uniqueName,
		Type:            mType,
		Depth:           depth,
		childNameCounts: make(map[string]int),
	}

	if parent != nil {
		parent.Children = append(parent.Children, m)
	} else {
		r.rootMeasurements = append(r.rootMeasurements, m)
	}

	var startErr error
	m.startRUsage, startErr = getRUsage(syscall.RUSAGE_SELF)
	if startErr != nil {
		return startErr
	}
	m.startRChildren, startErr = getRUsage(syscall.RUSAGE_CHILDREN)
	if startErr != nil {
		return startErr
	}
	m.startTime = time.Now()

	r.activeStack = append(r.activeStack, m)
	r.allMeasurements[uniqueName] = m
	return nil
}

// stop ends the active measurement identified by the provided conceptual name, recording its resource usage and duration.
func (r *Recorder) stop(conceptualName string) error {
	if len(r.activeStack) == 0 {
		return fmt.Errorf("cannot stop '%s': no active measurements", conceptualName)
	}
	m := r.activeStack[len(r.activeStack)-1]
	if m.ConceptualName != conceptualName {
		return fmt.Errorf("cannot stop '%s': the active measurement is '%s'", conceptualName, m.ConceptualName)
	}

	endTime := time.Now()
	endRUsage, err := getRUsage(syscall.RUSAGE_SELF)
	if err != nil {
		return err
	}
	endRChildren, err := getRUsage(syscall.RUSAGE_CHILDREN)
	if err != nil {
		return err
	}
	m.Inclusive.WallClock = endTime.Sub(m.startTime)
	m.Inclusive.UserTime = rtimeDifference(m.startRUsage.Utime, endRUsage.Utime) + rtimeDifference(m.startRChildren.Utime, endRChildren.Utime)
	m.Inclusive.SystemTime = rtimeDifference(m.startRUsage.Stime, endRUsage.Stime) + rtimeDifference(m.startRChildren.Stime, endRChildren.Stime)

	// Remove it from the active stack.
	r.activeStack = r.activeStack[:len(r.activeStack)-1]
	return nil
}

// RootMeasurements provides access to the start of the measurement trees for the analyzer.
func (r *Recorder) RootMeasurements() []*Measurement {
	return r.rootMeasurements
}

// PrintTree writes a visual representation of the measurement tree to the provided writer,
// up to a specified maximum depth. A maxDepth of -1 means print the entire tree.
func (r *Recorder) PrintTree(w io.Writer, maxDepth int, maxChildren int) {
	fmt.Fprintf(w, "--- Measurement Tree (Depth <= %d) ---\n", maxDepth)
	if maxDepth == -1 {
		maxDepth = 1000
	}
	if maxChildren == -1 {
		maxChildren = 1000
	}

	for i, root := range r.rootMeasurements {
		printNode(w, root, "", i == len(r.rootMeasurements)-1, maxDepth, maxChildren)
	}
}

// printNode writes a visual representation of a single node in the measurement tree to the provided writer.
// w is the io.Writer where the output is written.
// m is the current measurement node to be printed.
// prefix is the string prefix used to visually align the tree structure.
// isLast indicates whether this node is the last sibling in its parent's list of children.
// maxDepth is the maximum tree depth allowed to be processed and printed.
// maxChildren limits the number of children that can be displayed for a node.
func printNode(w io.Writer, m *Measurement, prefix string, isLast bool, maxDepth int, maxChildren int) {
	if m.Depth > maxDepth {
		return
	}

	fmt.Fprintf(w, "%s", prefix)
	if isLast {
		fmt.Fprint(w, "└── ")
	} else {
		fmt.Fprint(w, "├── ")
	}
	fmt.Fprintf(w, "%s (%s) - %s\n", m.UniqueName, m.Type, m.Inclusive.WallClock.Round(time.Microsecond))

	if isLast {
		prefix += "    " // The branch ended.
	} else {
		prefix += "│   " // The branch continues.
	}

	if m.Depth < maxDepth && len(m.Children) < maxChildren {
		for i, child := range m.Children {
			isLastChild := i == len(m.Children)-1
			printNode(w, child, prefix, isLastChild, maxDepth, maxChildren)
		}
	} else if len(m.Children) > 0 {
		// If we are at the max depth and this node has children.
		fmt.Fprintf(w, "%s    └── [... %d hidden ...]\n", prefix, len(m.Children))
	}
}

// --- OS and Time Utilities ---
func getRUsage(who int) (syscall.Rusage, error) {
	var rusage syscall.Rusage
	err := syscall.Getrusage(who, &rusage)
	return rusage, err
}

func rtimeDifference(start, end syscall.Timeval) time.Duration {
	startDuration := time.Duration(start.Sec)*time.Second + time.Duration(start.Usec)*time.Microsecond
	endDuration := time.Duration(end.Sec)*time.Second + time.Duration(end.Usec)*time.Microsecond
	return endDuration - startDuration
}
