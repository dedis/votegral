package io

import (
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg" // Register JPEG decoder
	_ "image/png"  // Register PNG decoder
	"io"
	"os"
	"os/exec"
	"time"
	"votegral/pkg/context"
	"votegral/pkg/log"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/oned"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"votegral/pkg/config"
)

// --- CoreReader (In-Memory Mock) ---

// CoreReader is a mock reader for the 'Core' hardware type. It reads data
// from an in-memory map instead of from files for testing pure computation.
type CoreReader struct {
	store map[string]Code
}

// NewCoreReader creates a new in-memory reader.
func NewCoreReader(store map[string]Code) *CoreReader {
	return &CoreReader{store: store}
}

// Read retrieves a code from the in-memory map.
func (r *CoreReader) Read(ctx *context.OperationContext, storage CodeStorage, codeType CodeType) (Code, error) {
	randData := storage.Load(codeType)
	if randData == "" {
		return nil, fmt.Errorf("no file path found in storage for code type %v", codeType)
	}

	return r.store[randData], nil
}

// --- PicReader (Reads from file) ---

// PicReader is the base file reader. It opens a PDF file, extracts an image,
// and decodes a barcode or QR code from it.
type PicReader struct {
	cfg *config.Config
}

func NewPicReader(cfg *config.Config) *PicReader {
	return &PicReader{cfg: cfg}
}

func (r *PicReader) Read(ctx *context.OperationContext, storage CodeStorage, codeType CodeType) (Code, error) {
	var code Code
	err := ctx.Recorder.Record("IO_PicReader.Read", func() error {
		filePath := storage.Load(codeType)
		if filePath == "" {
			return fmt.Errorf("no file path found in storage for code type %v", codeType)
		}

		// 1. Read the raw data from the image file.
		result, err := r.readCodeFromFile(filePath, codeType)
		if err != nil {
			return fmt.Errorf("failed to read code from file %s: %w", filePath, err)
		}

		// 2. Deserialize the raw data into a structured Code object.
		code, err = deserializeCode(result.GetText(), codeType)
		return err
	})
	return code, err
}

// readCodeFromFile handles opening a PDF, extracting images, and decoding.
func (r *PicReader) readCodeFromFile(filePath string, codeType CodeType) (*gozxing.Result, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", filePath, err)
	}
	defer file.Close()

	// pdfcpu is used to extract raw image data from the PDF wrapper.
	extractedImages, err := api.ExtractImagesRaw(file, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not extract images from PDF %s: %w", filePath, err)
	}

	if len(extractedImages) == 0 {
		return nil, fmt.Errorf("no images found in %s", filePath)
	}

	// Process the first extracted image.
	for _, imgs := range extractedImages {
		if len(imgs) > 0 {
			for _, img := range imgs {
				// Try to decode the image. A retry loop can handle intermittent read failures from camera.
				const maxRetries = 3
				for i := 0; i < maxRetries; i++ {
					decodedImage, err := decodeFromImage(img, codeType)
					if err == nil {
						return decodedImage, nil
					}
					time.Sleep(10 * time.Millisecond) // Small delay before retry
				}
				return nil, fmt.Errorf("failed to decode image from %s after %d retries", filePath, maxRetries)
			}
		}
	}

	return nil, fmt.Errorf("no processable image found in %s", filePath)
}

// decodeFromImage uses the gozxing library to find and decode a code within an image.
func decodeFromImage(reader io.Reader, codeType CodeType) (*gozxing.Result, error) {
	img, _, err := image.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("image.Decode failed: %w", err)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil, fmt.Errorf("gozxing.NewBinaryBitmapFromImage failed: %w", err)
	}

	hints := make(map[gozxing.DecodeHintType]interface{})
	var zxingReader gozxing.Reader

	if codeType == CheckInBarcodeType {
		zxingReader = oned.NewCode128Reader()
	} else {
		zxingReader = qrcode.NewQRCodeReader()
		hints[gozxing.DecodeHintType_PURE_BARCODE] = true
		hints[gozxing.DecodeHintType_TRY_HARDER] = true
	}

	return zxingReader.Decode(bmp, hints)
}

// deserializeCode is a factory function that creates the correct Code struct
// and populates it based on the raw string data from the scanner.
func deserializeCode(data string, codeType CodeType) (Code, error) {
	var code Code
	var rawBytes []byte
	var err error

	// QR codes are Base64 encoded, while barcodes are plain text.
	if codeType != CheckInBarcodeType {
		rawBytes, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode QR code data: %w", err)
		}
	} else {
		rawBytes = []byte(data)
	}

	switch codeType {
	case CheckInBarcodeType:
		code = &CheckInBarcode{}
	case CommitQRType:
		code = &CommitQR{}
	case EnvelopeQRType:
		code = &EnvelopeQR{}
	case CheckOutQRType:
		code = &CheckOutQR{}
	case ResponseQRType:
		code = &ResponseQR{}
	default:
		return nil, fmt.Errorf("unknown code type for deserialization: %v", codeType)
	}

	if err := code.Deserialize(rawBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize data for code type %v: %w", codeType, err)
	}

	return code, nil
}

// --- CamReader (Taking a picture) ---

// CamReader controls the scanner/camera to take a picture and then processes it with the help of PicReader.
type CamReader struct {
	picReader *PicReader
	cfg       *config.Config
}

func NewCamReader(cfg *config.Config) *CamReader {
	return &CamReader{
		picReader: NewPicReader(cfg),
		cfg:       cfg,
	}
}

// Read first takes a picture, then delegates to the PicReader.
func (cr *CamReader) Read(ctx *context.OperationContext, storage CodeStorage, codeType CodeType) (Code, error) {
	_ = ctx.Recorder.Record("IO_CamReader.TakePicture", func() error {
		scannedFile := cr.takePicture()
		storage.Save(codeType, scannedFile)
		return nil
	})
	return cr.picReader.Read(ctx, storage, codeType)
}

// takePicture executes an external command to capture an image.
func (cr *CamReader) takePicture() string {
	// Where to save the file.
	scannedFile := fmt.Sprintf("%s/image_%d.jpg", cr.cfg.PicturePath, time.Now().UnixNano())
	cmdName, args := cr.cfg.GetImageCommand(scannedFile)

	cmd := exec.Command(cmdName, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("failed to run camera command '%s': %w, output: %s", cmdName, err, string(output))
	}

	return scannedFile
}
