package store

import "nyx/internal/common"

const (
	ErrCodeInvalidFormat = "INVALID_REPOSITORY_FORMAT"
	ErrCodeNotFound      = "REPOSITORY_NOT_FOUND"
	ErrCodeReadFailed    = "REPOSITORY_READ_FAILED"
	ErrCodeWriteFailed   = "REPOSITORY_WRITE_FAILED"
)

func NewInvalidFormatError(msg string, err error) error {
	return common.NewError(ErrCodeInvalidFormat, msg, err)
}

func NewNotFoundError(msg string, err error) error {
	return common.NewError(ErrCodeNotFound, msg, err)
}

func NewReadFailedError(msg string, err error) error {
	return common.NewError(ErrCodeReadFailed, msg, err)
}

func NewWriteFailedError(msg string, err error) error {
	return common.NewError(ErrCodeWriteFailed, msg, err)
}
