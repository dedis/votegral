package hardware

import (
	"votegral/pkg/context"
	"votegral/pkg/io"
)

// CodeReader defines the ability to read a code (QR or barcode).
type CodeReader interface {
	Read(ctx *context.OperationContext, storage io.CodeStorage, codeType io.CodeType) (io.Code, error)
}

// CodeWriter defines the ability to write a code (QR or barcode).
type CodeWriter interface {
	Write(ctx *context.OperationContext, storage io.CodeStorage, code io.Code, cut bool) error
}

// Hardware is a composite interface representing a device with read/write capabilities.
type Hardware interface {
	CodeReader
	CodeWriter
	Name() string
}
