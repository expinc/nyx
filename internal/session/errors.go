package session

import "nyx/internal/common"

const (
	ErrCodeInvalidArgument = "INVALID_ARGUMENT"
	ErrCodeInvalidSession  = "INVALID_SESSION"
	ErrCodeSessionExpired  = "SESSION_EXPIRED"
	ErrCodeReadFailed      = "SESSION_READ_FAILED"
	ErrCodeWriteFailed     = "SESSION_WRITE_FAILED"
	ErrCodeDeleteFailed    = "SESSION_DELETE_FAILED"
)

func NewInvalidArgumentError(msg string, err error) error {
	return common.NewError(ErrCodeInvalidArgument, msg, err)
}

func NewInvalidSessionError(msg string, err error) error {
	return common.NewError(ErrCodeInvalidSession, msg, err)
}

func NewSessionExpiredError(msg string, err error) error {
	return common.NewError(ErrCodeSessionExpired, msg, err)
}

func NewReadFailedError(msg string, err error) error {
	return common.NewError(ErrCodeReadFailed, msg, err)
}

func NewWriteFailedError(msg string, err error) error {
	return common.NewError(ErrCodeWriteFailed, msg, err)
}

func NewDeleteFailedError(msg string, err error) error {
	return common.NewError(ErrCodeDeleteFailed, msg, err)
}
