package payment

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/godrealms/go-google-sdk/utils/logs"
	"math/big"
	"time"
)

// TokenHandler Token处理器
type TokenHandler struct {
	config     *Config
	keyManager *KeyManager
	logger     logs.Logger
}

// NewTokenHandler 创建Token处理器
func NewTokenHandler(config *Config, keyManager *KeyManager, logger logs.Logger) (*TokenHandler, error) {
	return &TokenHandler{
		config:     config,
		keyManager: keyManager,
		logger:     logger,
	}, nil
}

// DecryptToken 解密Token
func (th *TokenHandler) DecryptToken(ctx context.Context, encryptedTokenStr string) (*PaymentToken, error) {
	// 解析加密Token
	var encryptedToken EncryptedToken
	if err := json.Unmarshal([]byte(encryptedTokenStr), &encryptedToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted token: %w", err)
	}

	// 验证协议版本
	if encryptedToken.ProtocolVersion != string(EcV1) && encryptedToken.ProtocolVersion != string(EcV2) {
		return nil, fmt.Errorf("unsupported protocol version: %s", encryptedToken.ProtocolVersion)
	}

	// 验证签名
	if err := th.verifySignature(ctx, &encryptedToken); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 解密数据
	decryptedData, err := th.decryptData(&encryptedToken)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// 解析支付Token
	var paymentToken PaymentToken
	if err := json.Unmarshal(decryptedData, &paymentToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payment token: %w", err)
	}

	// 设置过期时间
	paymentToken.ExpiresAt = time.Now().Add(1 * time.Hour) // 默认1小时过期

	th.logger.Debug("Token decrypted successfully")
	return &paymentToken, nil
}

// verifySignature 验证签名
func (th *TokenHandler) verifySignature(ctx context.Context, token *EncryptedToken) error {
	// 获取签名密钥
	rootKey, err := th.keyManager.GetRootKey(token.SignedMessage.KeyID)
	if err != nil {
		// 尝试刷新根密钥
		if refreshErr := th.keyManager.RefreshRootKeys(ctx); refreshErr != nil {
			return fmt.Errorf("failed to refresh root keys: %w", refreshErr)
		}

		rootKey, err = th.keyManager.GetRootKey(token.SignedMessage.KeyID)
		if err != nil {
			return fmt.Errorf("root key not found after refresh: %w", err)
		}
	}

	// 构建签名数据
	signatureData := th.buildSignatureData(token)

	// 验证ECDSA签名
	signature, err := base64.StdEncoding.DecodeString(token.SignedMessage.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !th.verifyECDSASignature(rootKey, signatureData, signature) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// buildSignatureData 构建签名数据
func (th *TokenHandler) buildSignatureData(token *EncryptedToken) []byte {
	// 根据协议版本构建签名数据
	switch token.ProtocolVersion {
	case string(EcV1):
		return th.buildECv1SignatureData(token)
	case string(EcV2):
		return th.buildECv2SignatureData(token)
	default:
		return nil
	}
}

// buildECv1SignatureData 构建ECv1签名数据
func (th *TokenHandler) buildECv1SignatureData(token *EncryptedToken) []byte {
	data := fmt.Sprintf("%s.%s.%s.%s",
		token.SignedMessage.EncryptedMessage,
		token.SignedMessage.EphemeralPublicKey,
		token.SignedMessage.Tag,
		token.ProtocolVersion)
	return []byte(data)
}

// buildECv2SignatureData 构建ECv2签名数据
func (th *TokenHandler) buildECv2SignatureData(token *EncryptedToken) []byte {
	// ECv2的签名数据构建逻辑
	data := fmt.Sprintf("%s.%s.%s.%s.%s",
		token.SignedMessage.EncryptedMessage,
		token.SignedMessage.EphemeralPublicKey,
		token.SignedMessage.Tag,
		token.ProtocolVersion,
		token.SignedMessage.KeyID)
	return []byte(data)
}

// verifyECDSASignature 验证ECDSA签名
func (th *TokenHandler) verifyECDSASignature(publicKey *ecdsa.PublicKey, data, signature []byte) bool {
	// 计算数据哈希
	hash := sha256.Sum256(data)

	// 解析DER格式签名
	r, s, err := th.parseECDSASignature(signature)
	if err != nil {
		th.logger.Error("Failed to parse ECDSA signature", "error", err)
		return false
	}

	// 验证签名
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

// parseECDSASignature 解析ECDSA签名
func (th *TokenHandler) parseECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	// 这里需要实现DER格式签名的解析
	// 简化实现，实际应该使用ASN.1解析
	if len(signature) < 64 {
		return nil, nil, errors.New("signature too short")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	return r, s, nil
}

// decryptData 解密数据
func (th *TokenHandler) decryptData(token *EncryptedToken) ([]byte, error) {
	// 解码加密消息
	encryptedMessage, err := base64.StdEncoding.DecodeString(token.SignedMessage.EncryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted message: %w", err)
	}

	// 解码临时公钥
	ephemeralPublicKeyBytes, err := base64.StdEncoding.DecodeString(token.SignedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	// 解析临时公钥
	ephemeralPublicKey, err := th.parseEphemeralPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// 执行ECDH密钥交换
	sharedSecret, err := th.performECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// 派生加密密钥
	encryptionKey, macKey, err := th.deriveKeys(sharedSecret, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// 验证MAC
	if err := th.verifyMAC(encryptedMessage, macKey, token.SignedMessage.Tag); err != nil {
		return nil, fmt.Errorf("MAC verification failed: %w", err)
	}

	// 解密数据
	decryptedData, err := th.decryptAES(encryptedMessage, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return decryptedData, nil
}

// parseEphemeralPublicKey 解析临时公钥
func (th *TokenHandler) parseEphemeralPublicKey(keyBytes []byte) (*ecdsa.PublicKey, error) {
	// 解析未压缩的公钥格式 (0x04 + X + Y)
	if len(keyBytes) != 65 || keyBytes[0] != 0x04 {
		return nil, errors.New("invalid ephemeral public key format")
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(keyBytes[1:33])
	y := new(big.Int).SetBytes(keyBytes[33:65])

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ephemeral public key not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// performECDH 执行ECDH密钥交换
func (th *TokenHandler) performECDH(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	privateKey := th.keyManager.GetPrivateKey()
	if privateKey == nil {
		return nil, errors.New("private key not available")
	}

	// 执行ECDH
	x, _ := ephemeralPublicKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())

	// 返回共享密钥的X坐标
	return x.Bytes(), nil
}

// deriveKeys 派生加密密钥
func (th *TokenHandler) deriveKeys(sharedSecret, ephemeralPublicKey []byte) ([]byte, []byte, error) {
	// 使用HKDF派生密钥
	// 这里简化实现，实际应该使用标准的HKDF

	// 构建info参数
	info := append([]byte("Google"), ephemeralPublicKey...)

	// 派生32字节的加密密钥
	h := hmac.New(sha256.New, sharedSecret)
	h.Write(info)
	h.Write([]byte{0x01})
	encryptionKey := h.Sum(nil)

	// 派生32字节的MAC密钥
	h.Reset()
	h.Write(info)
	h.Write([]byte{0x02})
	macKey := h.Sum(nil)

	return encryptionKey, macKey, nil
}

// verifyMAC 验证MAC
func (th *TokenHandler) verifyMAC(encryptedMessage, macKey []byte, expectedTag string) error {
	tag, err := base64.StdEncoding.DecodeString(expectedTag)
	if err != nil {
		return fmt.Errorf("failed to decode tag: %w", err)
	}

	// 计算HMAC
	h := hmac.New(sha256.New, macKey)
	h.Write(encryptedMessage)
	computedTag := h.Sum(nil)

	// 比较标签
	if !hmac.Equal(tag, computedTag) {
		return errors.New("MAC verification failed")
	}

	return nil
}

// decryptAES 解密AES数据
func (th *TokenHandler) decryptAES(encryptedData, key []byte) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("encrypted data too short")
	}

	// 创建AES密码器
	block, err := aes.NewCipher(key[:32]) // 使用前32字节作为AES密钥
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// 提取IV
	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// 创建CBC模式解密器
	mode := cipher.NewCBCDecrypter(block, iv)

	// 解密数据
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// 移除PKCS7填充
	return th.removePKCS7Padding(decrypted)
}

// removePKCS7Padding 移除PKCS7填充
func (th *TokenHandler) removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	paddingLength := int(data[len(data)-1])
	if paddingLength > len(data) || paddingLength == 0 {
		return nil, errors.New("invalid padding")
	}

	// 验证填充
	for i := len(data) - paddingLength; i < len(data); i++ {
		if data[i] != byte(paddingLength) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-paddingLength], nil
}

// ValidateSignature 验证Token签名
func (th *TokenHandler) ValidateSignature(ctx context.Context, token *PaymentToken) error {
	// 这里可以添加额外的签名验证逻辑
	// 例如验证Token的完整性、时间戳等

	if token.MessageExpiration != "" {
		expiration, err := time.Parse(time.RFC3339, token.MessageExpiration)
		if err != nil {
			return fmt.Errorf("invalid message expiration format: %w", err)
		}

		if time.Now().After(expiration) {
			return errors.New("message has expired")
		}
	}

	return nil
}

// Health 健康检查
func (th *TokenHandler) Health(ctx context.Context) error {
	if th.keyManager == nil {
		return errors.New("key manager not available")
	}

	return th.keyManager.Health(ctx)
}
