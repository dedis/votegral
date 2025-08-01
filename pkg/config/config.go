package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"votegral/pkg/log"
)

const (
	// MaxEnvelopesToPrint is a safety limit to prevent accidentally sending thousands
	// of jobs to a physical printer during a large simulation run.
	MaxEnvelopesToPrint = 10
)

// SystemType defines the hardware platforms the simulation has been run on.
// Some hardware platforms have specific logic to operate peripherals
// successfully, see GetImageCommand()
type SystemType string

const (
	SystemMac   SystemType = "Mac"
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
	Voters              uint64
	FakeCredentialCount uint64
	Talliers            uint64
	HardwareType        HardwareType // "Core", "Disk" or "Peripheral"
	System              SystemType   // The hardware the system is being tested on.

	Printer      string // The name of the receipt printer, as named in CUPS
	PicturePath  string
	ResultsPath  string
	CUPSWaitTime int // Wait time for CUPS results in ms

	LogLevel     log.LogLevel
	PrintMetrics bool
	Seed         string
}

// NewConfig creates a new Config by parsing command-line flags.
func NewConfig() *Config {
	log.Debug("Parsing command-line flags...")
	voters := flag.Uint64("voters", 100, "Number of voters.")
	fakeCredentials := flag.Uint64("fake-creds", 0, "Number of fake credentials for each voter.")
	talliers := flag.Uint64("talliers", 4, "Number of election authority members.")
	hwType := flag.String("hw", "Core", "Hardware implementation (Core, Disk, Peripherals).")
	system := flag.String("system", "Mac", "System tag for logging (Mac, Kiosk, Pi, Xeon).")
	logLevel := flag.String("log-level", "info", "Set log level (trace, debug, info, error).")
	seed := flag.String("seed", "votegral", "Seed value for all randomly generated values.")
	printer := flag.String("printer", "TM", "Name of the printer in CUPS if Peripheral is set.")
	picPath := flag.String("pics", "output/pics/", "Path for storing pictures of physical materials.")
	resultsPath := flag.String("results", "output/results/", "Path for storing simulation results.")
	printMetrics := flag.Bool("print-metrics", false, "Whether to print detailed metrics during execution.")
	cupsWait := flag.Int("cups-wait", 100, "Wait time in ms for CUPS daemon to start.")

	flag.Parse()

	// Set Log Level
	setLogLevel(*logLevel)

	// Clean And Create Directory
	picPathClean := cleanAndCreateDirectory(*picPath)
	resultsPathClean := cleanAndCreateDirectory(*resultsPath)

	config := &Config{
		Voters:              *voters,
		FakeCredentialCount: *fakeCredentials,
		Talliers:            *talliers,
		System:              SystemType(*system),
		HardwareType:        HardwareType(*hwType),

		Printer:     *printer,
		PicturePath: picPathClean,
		ResultsPath: resultsPathClean,

		CUPSWaitTime: *cupsWait,
		PrintMetrics: *printMetrics,
		Seed:         *seed,
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
	case SystemMac:
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
	return fmt.Sprintf("Config{Voters:%d FakeCredentials:%d Talliers:%d System:%s "+
		"HW:%s Printer:%s PicPath:%s ResultsPath:%s CUPSWait:%d LogLevel:%d "+
		"PrintMetrics:%t Seeded:%s}",
		c.Voters, c.FakeCredentialCount, c.Talliers, c.System, c.HardwareType,
		c.Printer, c.PicturePath, c.ResultsPath, c.CUPSWaitTime,
		c.LogLevel, c.PrintMetrics, c.Seed)
}

// --- Config Helpers ---

// cleanAndCreateDirectory ensures the specified directory exists by and creating it if necessary.
// It returns the filepath.
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
