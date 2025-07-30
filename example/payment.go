package main

import (
	"context"
	"fmt"
	"github.com/godrealms/go-google-sdk/payment"
	"github.com/godrealms/go-google-sdk/utils/logs"
	"log"
	"time"
)

func main() {
	// 创建配置
	config := payment.DefaultConfig()
	config.Environment = payment.EnvironmentSandbox
	config.MerchantID = "your-merchant-id"
	config.PrivateKeyPath = "/path/to/your/private-key.pem"
	config.EnableDebugLog = true

	// 创建客户端
	client, err := payment.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// 健康检查
	ctx := context.Background()
	if err := client.Health(ctx); err != nil {
		log.Fatalf("Client health check failed: %v", err)
	}

	// 解密支付Token
	encryptedTokenStr := `{
		"protocolVersion": "ECv1",
		"signature": "...",
		"signedMessage": {
			"encryptedMessage": "...",
			"ephemeralPublicKey": "...",
			"tag": "..."
		}
	}`

	paymentToken, err := client.DecryptPaymentToken(ctx, encryptedTokenStr)
	if err != nil {
		log.Fatalf("Failed to decrypt payment token: %v", err)
	}

	// 验证Token
	if err := client.ValidatePaymentToken(ctx, paymentToken); err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	// 获取支付方法信息
	paymentInfo, err := client.GetPaymentMethodInfo(ctx, paymentToken)
	if err != nil {
		log.Fatalf("Failed to get payment method info: %v", err)
	}

	// 输出结果
	fmt.Printf("Payment Method: %s\n", paymentInfo.Type)
	fmt.Printf("Description: %s\n", paymentInfo.Description)
	fmt.Printf("Network: %s\n", paymentInfo.Network)
	fmt.Printf("Card Last 4: %s\n", paymentToken.GetCardLast4())
	fmt.Printf("Card Brand: %s\n", paymentToken.GetCardBrand())
}

// 高级使用示例
func advancedExample() {
	// 使用自定义配置
	config := &payment.Config{
		Environment:    payment.EnvironmentProduction,
		MerchantID:     "prod-merchant-id",
		MerchantName:   "My Store",
		PrivateKeyPath: "/secure/path/private-key.pem",
		Timeout:        45 * time.Second,
		MaxRetries:     5,
		CacheEnabled:   true,
		CacheTTL:       10 * time.Minute,
		LogLevel:       logs.LogLevelWarn,
		EnableDebugLog: false,
	}

	client, err := payment.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// 批量处理Token
	tokens := []string{
		"encrypted-token-1",
		"encrypted-token-2",
		"encrypted-token-3",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i, tokenStr := range tokens {
		paymentToken, err := client.DecryptPaymentToken(ctx, tokenStr)
		if err != nil {
			fmt.Printf("Failed to decrypt token %d: %v\n", i+1, err)
			continue
		}

		fmt.Printf("Token %d: %s ****%s\n",
			i+1,
			paymentToken.GetCardBrand(),
			paymentToken.GetCardLast4())
	}
}
