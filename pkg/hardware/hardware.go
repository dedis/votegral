package hardware

import (
	"fmt"
	"votegral/pkg/config"
	"votegral/pkg/context"
	"votegral/pkg/io"
)

// baseHardware provides common functionality for hardware implementations.
type baseHardware struct {
	reader CodeReader
	writer CodeWriter
}

func (h *baseHardware) Read(ctx *context.OperationContext, storage io.CodeStorage, codeType io.CodeType) (io.Code, error) {
	return h.reader.Read(ctx, storage, codeType)
}

func (h *baseHardware) Write(ctx *context.OperationContext, storage io.CodeStorage, code io.Code, cut bool) error {
	return h.writer.Write(ctx, storage, code, cut)
}

// Core is a mock hardware implementation that operates entirely in memory.
type Core struct {
	baseHardware
	inMemoryStore map[string]io.Code
}

func newCore() *Core {
	c := &Core{inMemoryStore: make(map[string]io.Code)}
	c.reader = io.NewCoreReader(c.inMemoryStore)
	c.writer = io.NewCoreWriter(c.inMemoryStore)
	return c
}

func (c *Core) Name() string { return "Core" }

// Disk simulates hardware that reads and writes files to disk.
type Disk struct {
	baseHardware
}

func newDisk(cfg *config.Config) *Disk {
	return &Disk{
		baseHardware: baseHardware{
			reader: io.NewPicReader(cfg),
			writer: io.NewSaveWriter(cfg),
		},
	}
}

func (d *Disk) Name() string { return "Disk" }

// Peripheral interacts with physical hardware like scanners and printers.
type Peripheral struct {
	baseHardware
}

func newPeripheral(cfg *config.Config) *Peripheral {
	return &Peripheral{
		baseHardware: baseHardware{
			reader: io.NewCamReader(cfg),
			writer: io.NewPrinterWriter(cfg),
		},
	}
}

func (p *Peripheral) Name() string { return "Peripheral" }

// New selects and creates the appropriate hardware implementation based on config.
func New(cfg *config.Config) (Hardware, error) {
	switch cfg.HardwareType {
	case config.HWCore:
		return newCore(), nil
	case config.HWDisk:
		return newDisk(cfg), nil
	case config.HWPeripheral:
		return newPeripheral(cfg), nil
	default:
		return nil, fmt.Errorf("unknown hardware type specified: %s", cfg.HardwareType)
	}
}
