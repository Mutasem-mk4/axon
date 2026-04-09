package errors

import "fmt"

// ErrorCode defines a set of standard error codes for the domain.
type ErrorCode string

const (
	// ErrCodeParseFailure is returned when a parser fails to process raw tool output.
	ErrCodeParseFailure ErrorCode = "PARSE_FAILURE"
	// ErrCodeValidation is returned when IEM validation fails.
	ErrCodeValidation ErrorCode = "VALIDATION_FAILED"
	// ErrCodeIO is returned for underlying I/O errors.
	ErrCodeIO ErrorCode = "IO_ERROR"
	// ErrCodeInternal is for unexpected system-level errors.
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"
	// ErrCodeThresholdExceeded is returned when the severity threshold is met or exceeded.
	ErrCodeThresholdExceeded ErrorCode = "THRESHOLD_EXCEEDED"
)

// DomainError implements the error interface with specialized metadata.
type DomainError struct {
	Code    ErrorCode
	Message string
	Err     error
}

// NewDomainError creates a new DomainError.
func NewDomainError(code ErrorCode, msg string, err error) error {
	return &DomainError{
		Code:    code,
		Message: msg,
		Err:     err,
	}
}

func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *DomainError) Unwrap() error {
	return e.Err
}
