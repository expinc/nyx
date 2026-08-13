package common

import "fmt"

// Error is a shared structured error type for internal packages.
type Error struct {
	Code string
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Msg, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewError(code, msg string, err error) *Error {
	return &Error{Code: code, Msg: msg, Err: err}
}
