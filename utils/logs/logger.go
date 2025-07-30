package logs

import (
	"log"
	"os"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Logger 日志接口
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// StandardLogger 标准日志实现
type StandardLogger struct {
	level       LogLevel
	enableDebug bool
	logger      *log.Logger
}

// NewLogger 创建日志器
func NewLogger(level LogLevel, enableDebug bool) Logger {
	return &StandardLogger{
		level:       level,
		enableDebug: enableDebug,
		logger:      log.New(os.Stdout, "[GooglePay] ", log.LstdFlags|log.Lshortfile),
	}
}

// Debug 调试日志
func (l *StandardLogger) Debug(msg string, args ...interface{}) {
	if !l.enableDebug || l.level != LogLevelDebug {
		return
	}
	l.logger.Printf("[DEBUG] "+msg, args...)
}

// Info 信息日志
func (l *StandardLogger) Info(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		l.logger.Printf("[INFO] "+msg, args...)
	}
}

// Warn 警告日志
func (l *StandardLogger) Warn(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelWarn) {
		l.logger.Printf("[WARN] "+msg, args...)
	}
}

// Error 错误日志
func (l *StandardLogger) Error(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelError) {
		l.logger.Printf("[ERROR] "+msg, args...)
	}
}

// shouldLog 判断是否应该记录日志
func (l *StandardLogger) shouldLog(level LogLevel) bool {
	levelOrder := map[LogLevel]int{
		LogLevelDebug: 0,
		LogLevelInfo:  1,
		LogLevelWarn:  2,
		LogLevelError: 3,
	}

	currentLevel, exists := levelOrder[l.level]
	if !exists {
		return true
	}

	targetLevel, exists := levelOrder[level]
	if !exists {
		return true
	}

	return targetLevel >= currentLevel
}
