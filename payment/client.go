package payment

import (
	"context"
	"errors"
	"fmt"
	"github.com/godrealms/go-google-sdk/utils/cache"
	"github.com/godrealms/go-google-sdk/utils/logs"
	"sync"
	"time"
)

// Client Google Pay客户端
type Client struct {
	config       *Config
	keyManager   *KeyManager
	tokenHandler *TokenHandler
	cache        cache.Cache
	logger       logs.Logger

	// 内部状态
	mu          sync.RWMutex
	initialized bool
	lastError   error
}

// NewClient 创建新的客户端
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := &Client{
		config: config,
		logger: logs.NewLogger(config.LogLevel, config.EnableDebugLog),
	}

	if err := client.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}

	return client, nil
}

// initialize 初始化客户端
func (c *Client) initialize() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 初始化密钥管理器
	keyManager, err := NewKeyManager(c.config, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	c.keyManager = keyManager

	// 初始化Token处理器
	tokenHandler, err := NewTokenHandler(c.config, c.keyManager, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create token handler: %w", err)
	}
	c.tokenHandler = tokenHandler

	// 初始化缓存
	if c.config.CacheEnabled {
		c.cache = cache.NewMemoryCache(c.config.CacheTTL)
	} else {
		c.cache = cache.NewNoOpCache()
	}

	c.initialized = true
	c.logger.Info("Google Pay client initialized successfully")

	return nil
}

// DecryptPaymentToken 解密支付Token
func (c *Client) DecryptPaymentToken(ctx context.Context, encryptedToken string) (*PaymentToken, error) {
	if !c.initialized {
		return nil, errors.New("client not initialized")
	}

	// 检查缓存
	if cached := c.cache.Get(encryptedToken); cached != nil {
		if token, ok := cached.(*PaymentToken); ok {
			c.logger.Debug("Payment token found in cache")
			return token, nil
		}
	}

	// 解密Token
	token, err := c.tokenHandler.DecryptToken(ctx, encryptedToken)
	if err != nil {
		c.logger.Error("Failed to decrypt payment token", "error", err)
		return nil, fmt.Errorf("decrypt token failed: %w", err)
	}

	// 缓存结果
	c.cache.Set(encryptedToken, token)

	c.logger.Info("Payment token decrypted successfully")
	return token, nil
}

// ValidatePaymentToken 验证支付Token
func (c *Client) ValidatePaymentToken(ctx context.Context, token *PaymentToken) error {
	if token == nil {
		return errors.New("token is nil")
	}

	// 验证Token有效期
	if time.Now().After(token.ExpiresAt) {
		return errors.New("token has expired")
	}

	// 验证签名
	if err := c.tokenHandler.ValidateSignature(ctx, token); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	c.logger.Info("Payment token validated successfully")
	return nil
}

// GetPaymentMethodInfo 获取支付方法信息
func (c *Client) GetPaymentMethodInfo(ctx context.Context, token *PaymentToken) (*PaymentMethodInfo, error) {
	if err := c.ValidatePaymentToken(ctx, token); err != nil {
		return nil, err
	}

	return &PaymentMethodInfo{
		Type:        token.PaymentMethodType,
		Description: token.PaymentMethodDescription,
		Network:     token.PaymentNetwork,
		Details:     token.PaymentMethodDetails,
	}, nil
}

// Health 健康检查
func (c *Client) Health(ctx context.Context) error {
	if !c.initialized {
		return errors.New("client not initialized")
	}

	// 检查密钥管理器
	if err := c.keyManager.Health(ctx); err != nil {
		return fmt.Errorf("key manager unhealthy: %w", err)
	}

	// 检查Token处理器
	if err := c.tokenHandler.Health(ctx); err != nil {
		return fmt.Errorf("token handler unhealthy: %w", err)
	}

	return nil
}

// Close 关闭客户端
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cache != nil {
		c.cache.Close()
	}

	if c.keyManager != nil {
		c.keyManager.Close()
	}

	c.initialized = false
	c.logger.Info("Google Pay client closed")

	return nil
}
