package crypto

import "nyx/internal/common"

const (
	ErrCodeInvalidParameter = "INVALID_PARAMETER"
	ErrCodeUnsupportedAlg   = "UNSUPPORTED_ALGORITHM"
	ErrCodeAuthFailed       = "AUTH_FAILED"
	ErrCodeInternal         = "INTERNAL_ERROR"
)

func NewInvalidParameterError(msg string, err error) error {
	return common.NewError(ErrCodeInvalidParameter, msg, err)
}

func NewUnsupportedAlgorithmError(msg string, err error) error {
	return common.NewError(ErrCodeUnsupportedAlg, msg, err)
}

func NewAuthFailedError(msg string, err error) error {
	return common.NewError(ErrCodeAuthFailed, msg, err)
}

func NewInternalError(msg string, err error) error {
	return common.NewError(ErrCodeInternal, msg, err)
}
