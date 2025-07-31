package errorx

import (
	"errors"
	"fmt"
)

// 预定义错误
var (
	ErrInvalidConfig         = errors.New("invalid configuration")
	ErrClientNotInitialized  = errors.New("client not initialized")
	ErrInvalidToken          = errors.New("invalid token")
	ErrTokenExpired          = errors.New("token expired")
	ErrSignatureVerification = errors.New("signature verification failed")
	ErrDecryptionFailed      = errors.New("decryption failed")
	ErrKeyNotFound           = errors.New("key not found")
	ErrUnsupportedProtocol   = errors.New("unsupported protocol version")
)

// PaymentError 支付错误
type PaymentError struct {
	Code    string
	Message string
	Cause   error
}

// Error 实现error接口
func (e *PaymentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap 实现错误解包
func (e *PaymentError) Unwrap() error {
	return e.Cause
}

// Is 实现错误比较
func (e *PaymentError) Is(target error) bool {
	if target == nil {
		return false
	}

	if pe, ok := target.(*PaymentError); ok {
		return e.Code == pe.Code
	}

	return errors.Is(e.Cause, target)
}

// NewPaymentError 创建支付错误
func NewPaymentError(code, message string, cause error) *PaymentError {
	return &PaymentError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// 错误代码常量
const (
	ErrorCodeInvalidConfig    = "INVALID_CONFIG"
	ErrorCodeNotInitialized   = "NOT_INITIALIZED"
	ErrorCodeInvalidToken     = "INVALID_TOKEN"
	ErrorCodeTokenExpired     = "TOKEN_EXPIRED"
	ErrorCodeSignatureFailed  = "SIGNATURE_FAILED"
	ErrorCodeDecryptionFailed = "DECRYPTION_FAILED"
	ErrorCodeKeyNotFound      = "KEY_NOT_FOUND"
	ErrorCodeNetworkError     = "NETWORK_ERROR"
	ErrorCodeInternalError    = "INTERNAL_ERROR"
)
