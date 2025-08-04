package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"votegral/pkg/log"
)

const (
	// MaxEnvelopesToPrint is a safety limit to prevent accidentally sending thousands
	// of jobs to a physical printer during a large simulation run.
	MaxEnvelopesToPrint = 10

	// MaxEnvelopesToSave same as MaxEnvelopesToPrint but for Disk I/O.
	MaxEnvelopesToSave = 1_000_000
)

// SystemType defines the hardware platforms the simulation has been run on.
// Some hardware platforms have specific logic to operate peripherals
// successfully -- see GetImageCommand()
type SystemType string

const (
	SystemLocal SystemType = "Local"
	SystemKiosk SystemType = "Kiosk"
	SystemPi    SystemType = "Pi"
	SystemXeon  SystemType = "Xeon"
)

// HardwareType defines the functional hardware implementation to use.
type HardwareType string

const (
	HWCore       HardwareType = "Core"        // In-memory mock, no I/O.
	HWDisk       HardwareType = "Disk"        // I/O by writing/reading bar/QR code files.
	HWPeripheral HardwareType = "Peripherals" // Run physical devices (printer/camera).
)

// Config holds all parameters for a simulation instance.
type Config struct {
	Runs     uint64       // Number of times to run the simulation
	LogLevel log.LogLevel // System logging level (trace, debug, info, error)
	TempPath string
	Cores    int // Number of cores (for parallelization)

	// System Parameters
	Voters              uint64 // Number of voters to simulate
	FakeCredentialCount uint64 // Number of fake credentials per voter
	EAMembers           uint64 // Number of entities involved with tallying
	ShuffleType         string // Type of shuffling (Neff, BayerGroth)

	// Peripherals and IO
	System       SystemType   // The hardware the system is being tested on.
	HardwareType HardwareType // "Core", "Disk" or "Peripheral"
	Printer      string       // The name of the receipt printer, as named in CUPS
	CUPSWaitTime int          // Wait time for CUPS results in ms
	PicturePath  string       // Path to store pictures (barcodes, QR codes)

	// Metrics Parameters
	PrintMetrics bool   // Print a tree showing all the recorded metrics
	MaxDepth     int    // The maximum depth of the metrics tree to print
	MaxChildren  int    // Maximum number of children to print for each node
	ResultsPath  string // The path to store the metrics data

	// Crypto parameters
	Seed string // Seed for deterministic random output
}

// NewConfig creates a new Config by parsing command-line flags.
func NewConfig() *Config {
	log.Debug("Parsing command-line flags...")
	runs := flag.Uint64("runs", 2, "Number of times to run the simulation.")
	cores := flag.Int("cores", 1, "Number of CPU cores (0 for All) - 1 for sequential run (w/ add. metrics)")
	voters := flag.Uint64("voters", 100, "Number of voters to simulate (registration + voting).")
	fakeCredentials := flag.Uint64("fake-creds", 1, "Number of fake credentials for each voter.")
	eaMembers := flag.Uint64("ea-members", 4, "Number of election authority members.")
	system := flag.String("system", "Local", "System tag (Local, Kiosk, Pi, Xeon) for logging and system-level logic.")
	hwType := flag.String("hw", "Core", "Hardware implementation (Core, Disk, Peripherals).")
	shuffleType := flag.String("shuffle", "Neff", "Type of Verifiable Shuffle (`Neff`, `BayerGroth`).")
	printer := flag.String("printer", "TM", "Name of the printer in CUPS if Peripheral is set.")
	cupsWait := flag.Int("cups-wait", 100, "Wait time in ms for CUPS daemon to start.")
	picPath := flag.String("pics", "output/pics/", "Path for storing pictures of physical materials.")
	resultsPath := flag.String("results", "output/results/", "Path for storing simulation results.")
	tempPath := flag.String("temp", "output/tmp/", "Path for storing temporary files.")
	printMetrics := flag.Bool("print-metrics", false, "Whether to print detailed metrics tree at the end.")
	maxDepth := flag.Int("max-depth", 2, "Maximum depth of the metrics tree to print")
	maxChildren := flag.Int("max-children", 10, "Maximum number of children to print for each node")
	seed := flag.String("seed", "votegral", "Seed for deterministic random output.")
	logLevel := flag.String("log-level", "info", "Set log level (trace, debug, info, error).")
	flag.Parse()

	setLogLevel(*logLevel)

	config := &Config{
		Runs:                *runs,
		Cores:               getCores(*cores),
		Voters:              *voters,
		FakeCredentialCount: *fakeCredentials,
		EAMembers:           *eaMembers,
		System:              SystemType(*system),
		HardwareType:        HardwareType(*hwType),
		Printer:             *printer,
		CUPSWaitTime:        *cupsWait,
		PicturePath:         cleanAndCreateDirectory(*picPath),
		ResultsPath:         cleanAndCreateDirectory(*resultsPath),
		TempPath:            cleanAndCreateDirectory(*tempPath),
		PrintMetrics:        *printMetrics,
		MaxDepth:            *maxDepth,
		MaxChildren:         *maxChildren,
		ShuffleType:         *shuffleType,
		Seed:                *seed,
	}
	log.Debug("Config: %s", config)
	return config
}

// GetImageCommand returns the command to take a picture for the configured system.
// SystemType affects logic only if HWPeripheral is chosen.
func (c *Config) GetImageCommand(outputPath string) (string, []string) {
	switch c.System {
	case SystemPi:
		return "libcamera-still", []string{"-o", outputPath, "--timeout", "1"}
	case SystemLocal:
		return "imagesnap", []string{outputPath}
	default:
		panic("Not implemented for system type: " + string(c.System))
	}
}

// GetPrintCommand returns the command to print a file on the receipt printer.
func (c *Config) GetPrintCommand(filePath string, cut bool) (string, []string) {
	args := []string{"-d", c.Printer, "-o", "fit-to-page", filePath}
	if cut {
		args = append(args, "-o", "TmxPaperCut=CutPerPage")
	}
	return "lp", args
}

// String returns a string representation of the Config instance
func (c *Config) String() string {
	return fmt.Sprintf("Config%+v", *c)
}

// --- Config Helpers ---

func getCores(cores int) int {
	if cores <= 0 {
		return runtime.NumCPU()
	}
	return cores
}

// cleanAndCreateDirectory ensures the specified directory exists by and creating it if necessary.
func cleanAndCreateDirectory(path string) string {
	path = filepath.Clean(path)
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("Failed to create directory %s: %v", path, err)
	}

	return path
}

// SetLogLevel sets the global log level to one of "trace", "debug", "info", or "error".
// Defaults to "info" on invalid input.
func setLogLevel(logLevel string) {
	switch logLevel {
	case "trace":
		log.SetLevel(log.LevelTrace)
	case "debug":
		log.SetLevel(log.LevelDebug)
	case "info":
		log.SetLevel(log.LevelInfo)
	case "error":
		log.SetLevel(log.LevelError)
	default:
		log.Info("Unknown log level '%s', defaulting to 'info'")
		log.SetLevel(log.LevelInfo)
	}
}
