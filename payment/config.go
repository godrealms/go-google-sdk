package payment

import (
	"errors"
	"github.com/godrealms/go-google-sdk/utils/logs"
	"time"
)

// Config Google Pay配置
type Config struct {
	// 环境配置
	Environment Environment `json:"environment"`

	// 商户配置
	MerchantID   string `json:"merchant_id"`
	MerchantName string `json:"merchant_name"`

	// 密钥配置
	PrivateKeyPath string `json:"private_key_path"`
	PrivateKeyData []byte `json:"-"` // 不序列化敏感数据

	// 网络配置
	Timeout    time.Duration `json:"timeout"`
	MaxRetries int           `json:"max_retries"`

	// 缓存配置
	CacheEnabled bool          `json:"cache_enabled"`
	CacheTTL     time.Duration `json:"cache_ttl"`

	// 日志配置
	LogLevel       logs.LogLevel `json:"log_level"`
	EnableDebugLog bool          `json:"enable_debug_log"`
}

// Environment 环境类型
type Environment string

const (
	EnvironmentSandbox    Environment = "sandbox"
	EnvironmentProduction Environment = "production"
)

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		Environment:    EnvironmentSandbox,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		CacheEnabled:   true,
		CacheTTL:       5 * time.Minute,
		LogLevel:       logs.LogLevelInfo,
		EnableDebugLog: false,
	}
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.MerchantID == "" {
		return errors.New("merchant_id is required")
	}

	if len(c.PrivateKeyData) == 0 && c.PrivateKeyPath == "" {
		return errors.New("private key is required")
	}

	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	if c.MaxRetries < 0 {
		c.MaxRetries = 3
	}

	return nil
}
