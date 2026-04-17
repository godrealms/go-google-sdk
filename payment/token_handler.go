package payment

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	"github.com/godrealms/go-google-sdk/utils/logs"
	"golang.org/x/crypto/hkdf"
)

// senderID is the constant sender identifier used in every signature payload.
// Google Pay issues all tokens as "Google".
const senderID = "Google"

// newAESCipher is overridable by tests.
var newAESCipher = aes.NewCipher

// TokenHandler decrypts Google Pay payment tokens and verifies their
// signature chain according to the Payment Method Token specification.
type TokenHandler struct {
	config     *Config
	keyManager *KeyManager
	logger     logs.Logger
}

// NewTokenHandler constructs a TokenHandler. config.MerchantID must be set —
// the merchant id is part of every signature payload (the "recipientId").
func NewTokenHandler(config *Config, keyManager *KeyManager, logger logs.Logger) (*TokenHandler, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if keyManager == nil {
		return nil, errors.New("key manager is nil")
	}
	if logger == nil {
		logger = logs.NewLogger(logs.LogLevelInfo, false)
	}
	return &TokenHandler{config: config, keyManager: keyManager, logger: logger}, nil
}

// DecryptToken parses the JSON-encoded encrypted token, verifies its
// signatures, and returns the decrypted PaymentToken.
func (th *TokenHandler) DecryptToken(ctx context.Context, encryptedTokenStr string) (*PaymentToken, error) {
	if th == nil {
		return nil, errors.New("token handler is nil")
	}
	if th.keyManager == nil {
		return nil, errors.New("token handler is not initialized")
	}

	var token EncryptedToken
	if err := json.Unmarshal([]byte(encryptedTokenStr), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted token: %w", err)
	}

	protocol := TokenProtocol(token.ProtocolVersion)
	if !protocol.IsValid() {
		return nil, fmt.Errorf("unsupported protocol version: %s", token.ProtocolVersion)
	}

	// Verify the signature chain and recover the public key that signed
	// the SignedMessage bytes.
	if err := th.verifyTokenSignature(ctx, &token, protocol); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse the signed message envelope.
	var payload SignedMessagePayload
	if err := json.Unmarshal([]byte(token.SignedMessage), &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed message: %w", err)
	}

	plaintext, err := th.decryptPayload(&payload)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var paymentToken PaymentToken
	if err := json.Unmarshal(plaintext, &paymentToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payment token: %w", err)
	}

	if paymentToken.MessageExpiration != "" {
		expiresAt, err := parseMsTimestamp(paymentToken.MessageExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid message expiration format: %w", err)
		}
		paymentToken.ExpiresAt = expiresAt
	}
	if paymentToken.ExpiresAt.IsZero() {
		paymentToken.ExpiresAt = time.Now().Add(1 * time.Hour)
	}
	if time.Now().After(paymentToken.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	paymentToken.DecryptedAt = time.Now()
	th.logger.Debug("Token decrypted successfully")
	return &paymentToken, nil
}

// verifyTokenSignature verifies the outer signature (ECv1) or the full
// intermediate-key chain (ECv2). On success the ECv2 path has established that
// the SignedMessage was signed by a Google-issued intermediate key.
func (th *TokenHandler) verifyTokenSignature(ctx context.Context, token *EncryptedToken, protocol TokenProtocol) error {
	switch protocol {
	case EcV1:
		return th.verifyECv1(ctx, token)
	case EcV2:
		return th.verifyECv2(ctx, token)
	default:
		return fmt.Errorf("unsupported protocol version: %s", protocol)
	}
}

func (th *TokenHandler) verifyECv1(ctx context.Context, token *EncryptedToken) error {
	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	data := signatureDataECv1(th.recipientID(), token.SignedMessage)

	rootKeys, err := th.collectRootKeys(ctx)
	if err != nil {
		return err
	}
	if verifyWithAnyKey(rootKeys, data, sig) {
		return nil
	}
	return errors.New("no root key verified the ECv1 signature")
}

func (th *TokenHandler) verifyECv2(ctx context.Context, token *EncryptedToken) error {
	if token.IntermediateSigningKey == nil {
		return errors.New("ECv2 token missing intermediateSigningKey")
	}

	// Step 1: verify the intermediate signed-key block against Google root keys.
	intermediateData := signatureDataECv2Intermediate(token.IntermediateSigningKey.SignedKey)

	rootKeys, err := th.collectRootKeys(ctx)
	if err != nil {
		return err
	}

	var intermediateVerified bool
	for _, rawSig := range token.IntermediateSigningKey.Signatures {
		sig, err := base64.StdEncoding.DecodeString(rawSig)
		if err != nil {
			continue
		}
		if verifyWithAnyKey(rootKeys, intermediateData, sig) {
			intermediateVerified = true
			break
		}
	}
	if !intermediateVerified {
		return errors.New("no root key verified the intermediate signing key")
	}

	// Step 2: parse the intermediate signed key and check expiration.
	var signedKey IntermediateSignedKey
	if err := json.Unmarshal([]byte(token.IntermediateSigningKey.SignedKey), &signedKey); err != nil {
		return fmt.Errorf("parse intermediate signed key: %w", err)
	}
	if signedKey.KeyExpiration != "" {
		expiry, err := parseMsTimestamp(signedKey.KeyExpiration)
		if err != nil {
			return fmt.Errorf("invalid intermediate key expiration: %w", err)
		}
		if !time.Now().Before(expiry) {
			return errors.New("intermediate signing key has expired")
		}
	}

	intermediatePub, err := parseECDSAPublicKeyBase64(signedKey.KeyValue)
	if err != nil {
		return fmt.Errorf("parse intermediate public key: %w", err)
	}

	// Step 3: verify the outer signature over the signed message using the
	// intermediate key.
	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return fmt.Errorf("decode outer signature: %w", err)
	}
	data := signatureDataECv2Message(th.recipientID(), token.SignedMessage)
	if !verifyECDSA(intermediatePub, data, sig) {
		return errors.New("intermediate key did not verify signedMessage signature")
	}
	return nil
}

// decryptPayload performs ECDH + HKDF + MAC verification + AES-256-CTR
// decryption per the spec.
func (th *TokenHandler) decryptPayload(payload *SignedMessagePayload) ([]byte, error) {
	encryptedMessage, err := base64.StdEncoding.DecodeString(payload.EncryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted message: %w", err)
	}
	ephemeralPublicKeyBytes, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(payload.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	ephemeralPublicKey, err := parseUncompressedP256(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	sharedSecret, err := th.performECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	symKey, macKey, err := deriveKeys(sharedSecret, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	if err := verifyMAC(encryptedMessage, macKey, tag); err != nil {
		return nil, err
	}

	plaintext, err := decryptAESCTR(encryptedMessage, symKey)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}
	return plaintext, nil
}

// performECDH multiplies the merchant private key with the ephemeral public
// key and returns the X coordinate of the shared point, as raw big-endian
// bytes.
func (th *TokenHandler) performECDH(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	if ephemeralPublicKey == nil {
		return nil, errors.New("ephemeral public key is nil")
	}
	if ephemeralPublicKey.Curve == nil {
		return nil, errors.New("ephemeral public key curve is nil")
	}
	privateKey := th.keyManager.GetPrivateKey()
	if privateKey == nil {
		return nil, errors.New("private key not available")
	}
	if privateKey.D == nil {
		return nil, errors.New("private key scalar is nil")
	}
	x, _ := ephemeralPublicKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("ECDH produced nil shared secret")
	}
	// Return the X coordinate as a fixed-length 32-byte big-endian slice —
	// HKDF input needs stable length.
	out := make([]byte, 32)
	xBytes := x.Bytes()
	copy(out[32-len(xBytes):], xBytes)
	return out, nil
}

// collectRootKeys returns the current Google root public keys, refreshing the
// cache once if empty.
func (th *TokenHandler) collectRootKeys(ctx context.Context) ([]*ecdsa.PublicKey, error) {
	keys := th.keyManager.AllRootKeys()
	if len(keys) > 0 {
		return keys, nil
	}
	if err := th.keyManager.RefreshRootKeys(ctx); err != nil {
		return nil, fmt.Errorf("refresh root keys: %w", err)
	}
	keys = th.keyManager.AllRootKeys()
	if len(keys) == 0 {
		return nil, errors.New("no Google root keys available")
	}
	return keys, nil
}

func (th *TokenHandler) recipientID() string {
	if th.config == nil {
		return "merchant:"
	}
	return "merchant:" + th.config.MerchantID
}

// ValidateSignature performs lightweight post-decryption checks on a
// PaymentToken — currently just the message expiration timestamp. The full
// signature chain is already verified during decryption.
func (th *TokenHandler) ValidateSignature(_ context.Context, token *PaymentToken) error {
	if token == nil {
		return errors.New("token is nil")
	}
	if token.MessageExpiration != "" {
		expiration, err := parseMsTimestamp(token.MessageExpiration)
		if err != nil {
			return fmt.Errorf("invalid message expiration format: %w", err)
		}
		if time.Now().After(expiration) {
			return errors.New("message has expired")
		}
	}
	return nil
}

// Health reports whether the handler's dependencies are in a usable state.
func (th *TokenHandler) Health(ctx context.Context) error {
	if th.keyManager == nil {
		return errors.New("key manager not available")
	}
	return th.keyManager.Health(ctx)
}

// --- Signature payload construction (toLengthValue concatenation). ---------

// toLengthValue prefixes value with its length encoded as 4-byte little-endian.
func toLengthValue(value string) []byte {
	buf := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(value)))
	copy(buf[4:], value)
	return buf
}

func signatureDataECv1(recipientID, signedMessage string) []byte {
	return concat(
		toLengthValue(senderID),
		toLengthValue(recipientID),
		toLengthValue(string(EcV1)),
		toLengthValue(signedMessage),
	)
}

func signatureDataECv2Intermediate(signedKey string) []byte {
	return concat(
		toLengthValue(senderID),
		toLengthValue(string(EcV2)),
		toLengthValue(signedKey),
	)
}

func signatureDataECv2Message(recipientID, signedMessage string) []byte {
	return concat(
		toLengthValue(senderID),
		toLengthValue(recipientID),
		toLengthValue(string(EcV2)),
		toLengthValue(signedMessage),
	)
}

func concat(parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := make([]byte, 0, size)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- Crypto primitives. -----------------------------------------------------

// deriveKeys runs HKDF-SHA256 per the Google Pay spec:
//
//	IKM  = ephemeralPublicKey || sharedSecret
//	salt = 32 zero bytes (default for HKDF-SHA256 when no salt is supplied)
//	info = "Google"
//	L    = 64 (32 AES key + 32 MAC key)
func deriveKeys(sharedSecret, ephemeralPublicKey []byte) ([]byte, []byte, error) {
	if len(sharedSecret) == 0 {
		return nil, nil, errors.New("shared secret is empty")
	}
	if len(ephemeralPublicKey) == 0 {
		return nil, nil, errors.New("ephemeral public key is empty")
	}
	ikm := append(append([]byte{}, ephemeralPublicKey...), sharedSecret...)
	reader := hkdf.New(sha256.New, ikm, nil /* salt */, []byte(senderID))
	out := make([]byte, 64)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, nil, fmt.Errorf("hkdf read: %w", err)
	}
	return out[:32], out[32:], nil
}

func verifyMAC(ciphertext, macKey, tag []byte) error {
	if len(macKey) == 0 {
		return errors.New("mac key is empty")
	}
	h := hmac.New(sha256.New, macKey)
	h.Write(ciphertext)
	if !hmac.Equal(tag, h.Sum(nil)) {
		return errors.New("MAC verification failed")
	}
	return nil
}

// decryptAESCTR decrypts using AES-256-CTR with a zero IV, matching the
// Google Pay spec. No PKCS7 padding is used in CTR mode.
func decryptAESCTR(ciphertext, key []byte) ([]byte, error) {
	if len(key) < 32 {
		return nil, errors.New("invalid AES key length")
	}
	block, err := newAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func verifyECDSA(pub *ecdsa.PublicKey, data, sig []byte) bool {
	if pub == nil {
		return false
	}
	hash := sha256.Sum256(data)
	r, s, err := parseECDSASignature(sig)
	if err != nil {
		return false
	}
	return ecdsa.Verify(pub, hash[:], r, s)
}

func verifyWithAnyKey(keys []*ecdsa.PublicKey, data, sig []byte) bool {
	for _, k := range keys {
		if verifyECDSA(k, data, sig) {
			return true
		}
	}
	return false
}

// parseECDSASignature accepts both raw (r||s, 64 bytes for P-256) and DER
// ASN.1-encoded signatures.
func parseECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) == 64 {
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if r.Sign() == 0 || s.Sign() == 0 {
			return nil, nil, errors.New("invalid signature values")
		}
		return r, s, nil
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return nil, nil, fmt.Errorf("failed to parse signature: %w", err)
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() == 0 || sig.S.Sign() == 0 {
		return nil, nil, errors.New("invalid signature values")
	}
	return sig.R, sig.S, nil
}

// parseUncompressedP256 parses a 65-byte 0x04||X||Y P-256 public key.
func parseUncompressedP256(keyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(keyBytes) != 65 || keyBytes[0] != 0x04 {
		return nil, errors.New("invalid ephemeral public key format")
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(keyBytes[1:33])
	y := new(big.Int).SetBytes(keyBytes[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ephemeral public key not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// parseECDSAPublicKeyBase64 parses a base64-encoded SubjectPublicKeyInfo
// (DER) as delivered inside Google's signed key and root key payloads.
func parseECDSAPublicKeyBase64(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}
	return ec, nil
}

// parseMsTimestamp parses a millisecond-since-epoch timestamp (as Google
// encodes keyExpiration / messageExpiration) or, if that fails, an RFC3339
// timestamp. The RFC3339 fallback keeps backwards compatibility with any
// callers that populated MessageExpiration themselves.
func parseMsTimestamp(value string) (time.Time, error) {
	if ms, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.UnixMilli(ms), nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("not an RFC3339 or ms-timestamp value: %q", value)
}
