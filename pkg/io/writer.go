package io

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/jung-kurt/gofpdf"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/oned"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode/decoder"
	"image"
	"image/jpeg"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"time"
	"votegral/pkg/config"
	"votegral/pkg/context"
	"votegral/pkg/metrics"
)

const (
	qrCodeSize     = 512
	barcodeWidth   = 300
	barcodeHeight  = 100
	pdfPointsPerMM = 2.8346
)

// --- CoreWriter (In-Memory Mock) ---

// CoreWriter is a mock writer for the 'Core' hardware type. It writes data
// to an in-memory map instead of to files.
type CoreWriter struct {
	// Key Value store
	store map[string]Code
}

// NewCoreWriter creates a new in-memory writer.
func NewCoreWriter(store map[string]Code) *CoreWriter {
	return &CoreWriter{store: store}
}

// Write stores a code in the in-memory map.
func (w *CoreWriter) Write(ctx *context.OperationContext, storage CodeStorage, code Code, cut bool) error {
	// Save the object as (key, value) store
	serializedData, err := code.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize code type %v: %w", code.Type(), err)
	}
	w.store[string(serializedData)] = code

	storage.Save(code.Type(), string(serializedData))

	return nil
}

// --- SaveWriter (Writes to file) ---

// SaveWriter is the base file writer. It generates a code image (QR/barcode),
// wraps it in a PDF, and saves it to a file on disk.
type SaveWriter struct {
	cfg *config.Config
}

// NewSaveWriter creates a writer that saves codes to PDF files.
func NewSaveWriter(cfg *config.Config) *SaveWriter {
	return &SaveWriter{cfg: cfg}
}

// Write orchestrates serializing, encoding, and saving a code to a PDF file.
func (w *SaveWriter) Write(ctx *context.OperationContext, storage CodeStorage, code Code, cut bool) error {
	return ctx.Recorder.Record("SaveFile_"+code.Type().String(), metrics.MDiskWrite, func() error {
		// 1. Generate the image of the code.
		img, err := w.generateCodeImage(code)
		if err != nil {
			return err
		}

		// 2. Create the output file.
		filePath := fmt.Sprintf("%s/code_%d_%d.pdf", w.cfg.PicturePath, code.Type(), rand.Int31())
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", filePath, err)
		}
		defer file.Close()

		// 3. Write the image into a PDF wrapper.
		if err := writeImageToPDF(img, file); err != nil {
			return fmt.Errorf("failed to write image to PDF %s: %w", filePath, err)
		}

		// 4. Record the file's location in the provided storage object.
		storage.Save(code.Type(), filePath)
		return nil
	})
}

// generateCodeImage creates an image.Image from a Code object.
func (w *SaveWriter) generateCodeImage(code Code) (image.Image, error) {
	serializedData, err := code.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize code type %v: %w", code.Type(), err)
	}

	var encoder gozxing.Writer
	var format gozxing.BarcodeFormat
	var width, height int
	var hints map[gozxing.EncodeHintType]interface{}
	var data string

	if code.Type() == CheckInBarcodeType {
		encoder = oned.NewCode128Writer()
		format = gozxing.BarcodeFormat_CODE_128
		width, height = barcodeWidth, barcodeHeight
		data = string(serializedData) // Barcode data is plain text
	} else {
		encoder = qrcode.NewQRCodeWriter()
		format = gozxing.BarcodeFormat_QR_CODE
		width, height = qrCodeSize, qrCodeSize
		hints = map[gozxing.EncodeHintType]interface{}{
			gozxing.EncodeHintType_ERROR_CORRECTION: decoder.ErrorCorrectionLevel_M,
		}
		// QR code data is Base64 encoded to handle arbitrary binary data.
		data = base64.StdEncoding.EncodeToString(serializedData)
	}

	return encoder.Encode(data, format, width, height, hints)
}

// --- PrinterWriter (Simulates printing) ---

// PrinterWriter decorates a SaveWriter by also simulating sending the file to a printer.
type PrinterWriter struct {
	saveWriter *SaveWriter
	cfg        *config.Config
}

// NewPrinterWriter creates a writer that saves to a file and then "prints" it.
func NewPrinterWriter(cfg *config.Config) *PrinterWriter {
	return &PrinterWriter{
		saveWriter: NewSaveWriter(cfg),
		cfg:        cfg,
	}
}

// Write first saves the code to a file, then simulates printing it.
func (w *PrinterWriter) Write(ctx *context.OperationContext, storage CodeStorage, code Code, cut bool) error {
	// First, create the file on disk using the SaveWriter.
	if err := w.saveWriter.Write(ctx, storage, code, cut); err != nil {
		return err
	}

	// Then, record the performance of the printing operation.
	return ctx.Recorder.Record("Print_"+code.Type().String(), metrics.MHardwareWrite, func() error {
		filePath := storage.Load(code.Type())
		return w.printFile(filePath, cut)
	})
}

// printFile handles the logic of interacting with the CUPS printing system.
func (w *PrinterWriter) printFile(filePath string, cut bool) error {
	_ = exec.Command("killall", "cupsd").Run() // Force restart for clean measurement

	cupsDaemon := exec.Command("/usr/sbin/cupsd", "-f")
	if err := cupsDaemon.Start(); err != nil {
		return fmt.Errorf("failed to start cupsd: %w", err)
	}

	// Give the daemon a moment to initialize.
	time.Sleep(time.Duration(w.cfg.CUPSWaitTime) * time.Millisecond)

	cmdName, args := w.cfg.GetPrintCommand(filePath, cut)
	cmd := exec.Command(cmdName, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = cupsDaemon.Process.Kill()
		return fmt.Errorf("print command '%s' failed: %w, output: %s", cmdName, err, string(output))
	}

	// Wait for the CUPS daemon to exit, which it does after the job is processed.
	// This is a blocking call that gives us a good measure of the total print job time.
	_ = cupsDaemon.Wait()

	return nil
}

// --- PDF Utility ---

// writeImageToPDF embeds an image into a new PDF and writes it to an io.Writer.
func writeImageToPDF(img image.Image, w io.Writer) error {
	// Encode the image to JPEG format in memory.
	buf := new(bytes.Buffer)
	if err := jpeg.Encode(buf, img, &jpeg.Options{Quality: 95}); err != nil {
		return fmt.Errorf("jpeg encoding failed: %w", err)
	}

	// Calculate image dimensions in millimeters for the PDF page size.
	widthMM := float64(img.Bounds().Dx()) / pdfPointsPerMM
	heightMM := float64(img.Bounds().Dy()) / pdfPointsPerMM

	pageSize := gofpdf.SizeType{Wd: widthMM, Ht: heightMM}

	pdf := gofpdf.NewCustom(&gofpdf.InitType{
		UnitStr: "mm",
		Size:    pageSize,
	})
	pdf.AddPageFormat("P", pageSize)

	// Register the in-memory JPEG data.
	options := gofpdf.ImageOptions{ImageType: "JPEG", ReadDpi: true}
	pdf.RegisterImageOptionsReader("code.jpg", options, buf)

	// Place the image on the page, filling it completely.
	pdf.ImageOptions("code.jpg", 0, 0, widthMM, heightMM, false, options, 0, "")

	return pdf.Output(w)
}
