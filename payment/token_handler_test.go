package payment

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/godrealms/go-google-sdk/utils/logs"
)

func TestTokenHandlerNewRejectsNilDependencies(t *testing.T) {
	if _, err := NewTokenHandler(nil, &KeyManager{}, logs.NewLogger(logs.LogLevelInfo, false)); err == nil {
		t.Fatalf("expected nil config error")
	}

	if _, err := NewTokenHandler(&Config{MerchantID: "merchant"}, nil, logs.NewLogger(logs.LogLevelInfo, false)); err == nil {
		t.Fatalf("expected nil key manager error")
	}

	h, err := NewTokenHandler(&Config{MerchantID: "merchant"}, &KeyManager{}, logs.NewLogger(logs.LogLevelInfo, false))
	if err != nil {
		t.Fatalf("expected successful constructor: %v", err)
	}
	if h == nil {
		t.Fatalf("expected handler instance")
	}
}

func TestTokenHandlerParseECDSASignatureRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	if _, _, err := h.parseECDSASignature(make([]byte, 64)); err == nil {
		t.Fatalf("expected zero signature values to be rejected")
	}

	if _, _, err := h.parseECDSASignature([]byte("invalid")); err == nil {
		t.Fatalf("expected malformed signature bytes to be rejected")
	}
}

func TestTokenHandlerVerifyECDSASignatureRejectsNilPublicKey(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if ok := h.verifyECDSASignature(nil, []byte("data"), []byte("sig")); ok {
		t.Fatalf("expected nil public key verification to fail")
	}
}

func TestTokenHandlerVerifyECDSASignatureSucceedsForValidASN1(t *testing.T) {
	t.Parallel()

	priv := newECKeyPair(t)
	data := []byte("signed payload")

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if !h.verifyECDSASignature(&priv.PublicKey, data, ecdsaSignatureASN1(t, priv, data)) {
		t.Fatalf("expected valid signature to verify")
	}
}

func TestTokenHandlerVerifyECDSASignatureRejectsIncorrectSignature(t *testing.T) {
	t.Parallel()

	priv := newECKeyPair(t)
	data := []byte("signed payload")
	wrong := []byte("different payload")

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if h.verifyECDSASignature(&priv.PublicKey, data, ecdsaSignatureASN1(t, priv, wrong)) {
		t.Fatalf("expected signature mismatch to fail")
	}
}

func TestTokenHandlerValidateSignatureHandlesRawAndMalformedExpiration(t *testing.T) {
	h := &TokenHandler{}
	if err := h.ValidateSignature(context.Background(), &PaymentToken{}); err != nil {
		t.Fatalf("expected empty expiration to pass validation: %v", err)
	}

	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: "bad-time"}); err == nil {
		t.Fatalf("expected invalid expiration format to fail")
	}
}

func TestTokenHandlerValidateSignatureAcceptsFutureExpiration(t *testing.T) {
	h := &TokenHandler{}
	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: nowWithOffset(time.Hour).Format(time.RFC3339)}); err != nil {
		t.Fatalf("expected valid future expiration, got %v", err)
	}
}

func TestTokenHandlerBuildSignatureDataSupportsEcV2(t *testing.T) {
	h := &TokenHandler{}
	enc := &EncryptedToken{ProtocolVersion: string(EcV2), SignedMessage: SignedMessage{
		EncryptedMessage:   "enc",
		EphemeralPublicKey: "epk",
		Tag:                "tag",
		KeyID:              "root-1",
	}}

	sigData, err := h.buildSignatureData(enc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(sigData) != "enc.epk.tag.ECv2.root-1" {
		t.Fatalf("unexpected ecv2 signature data: %s", string(sigData))
	}
}

func TestTokenHandlerParseECDSASignatureAcceptsRaw64ByteSignature(t *testing.T) {
	t.Parallel()

	private := newECKeyPair(t)
	data := []byte("raw-signature")
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, private, hash[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		t.Fatalf("unexpected r/s length: %d %d", len(rBytes), len(sBytes))
	}

	raw := make([]byte, 64)
	copy(raw[32-len(rBytes):32], rBytes)
	copy(raw[64-len(sBytes):64], sBytes)

	hdl := &TokenHandler{}
	parsedR, parsedS, parseErr := hdl.parseECDSASignature(raw)
	if parseErr != nil {
		t.Fatalf("expected raw signature to parse: %v", parseErr)
	}
	if parsedR == nil || parsedS == nil {
		t.Fatalf("expected parsed signature values")
	}

	if parsedR.Cmp(r) != 0 || parsedS.Cmp(s) != 0 {
		t.Fatalf("parsed signature mismatch")
	}
}

func TestTokenHandlerParseECDSASignatureRejectsZeroValues(t *testing.T) {
	h := &TokenHandler{}

	zeroSig, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: big.NewInt(0), S: big.NewInt(0)})
	if err != nil {
		t.Fatalf("marshal zero signature: %v", err)
	}

	if _, _, err := h.parseECDSASignature(zeroSig); err == nil {
		t.Fatalf("expected zero-value signature components to fail")
	}
}

func TestTokenHandlerDecryptTokenRejectsUnsupportedProtocol(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false), keyManager: &KeyManager{}}

	_, err := h.DecryptToken(context.Background(), `{"protocolVersion":"ECv3"}`)
	if err == nil {
		t.Fatalf("expected unsupported protocol error")
	}
}

func TestTokenHandlerDecryptTokenRejectsInvalidJSON(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false), keyManager: &KeyManager{}}
	_, err := h.DecryptToken(context.Background(), "{invalid")
	if err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestTokenHandlerDecryptTokenRejectsMissingKeyManager(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	_, err := h.DecryptToken(context.Background(), `{"protocolVersion":"ECv1","signedMessage":{}}`)
	if err == nil || !strings.Contains(err.Error(), "token handler is not initialized") {
		t.Fatalf("expected missing key manager error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsInvalidSignature(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)

	encryptedToken := buildEncryptedTokenFromPayload(t, leaf, root, map[string]any{
		"paymentMethodType": "CARD",
	}, EcV1, "root-1")

	var token EncryptedToken
	if err := json.Unmarshal([]byte(encryptedToken), &token); err != nil {
		t.Fatalf("unmarshal prepared token: %v", err)
	}

	token.SignedMessage.Signature = "invalid-signature"
	bytes, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal prepared token: %v", err)
	}

	h := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey},
		},
	}

	if _, err := h.DecryptToken(context.Background(), string(bytes)); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature verification failure, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsInvalidPaymentPayloadJSON(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)

	tokenStr := buildEncryptedTokenFromPayloadBytes(t, leaf, root, []byte("not-json"), EcV1, "root-1")
	h := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey},
		},
	}

	if _, err := h.DecryptToken(context.Background(), tokenStr); err == nil || !strings.Contains(err.Error(), "failed to unmarshal payment token") {
		t.Fatalf("expected payment token unmarshal error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsDecryptionFailure(t *testing.T) {
	rootKey := newECKeyPair(t)
	enc := &EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   "",
			EphemeralPublicKey: "",
			Tag:                "",
			KeyID:              "root-1",
		},
	}
	enc.SignedMessage.Signature = encodeSignature(t, rootKey, enc)

	tokenBytes, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}

	h2 := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{rootKeys: map[string]*ecdsa.PublicKey{
			"root-1": &rootKey.PublicKey,
		}},
	}

	_, err = h2.DecryptToken(context.Background(), string(tokenBytes))
	if err == nil {
		t.Fatalf("expected decryption error")
	}
}

func TestTokenHandlerNewUsesDefaultLoggerWhenNil(t *testing.T) {
	h, err := NewTokenHandler(&Config{MerchantID: "merchant"}, &KeyManager{}, nil)
	if err != nil {
		t.Fatalf("expected constructor success: %v", err)
	}

	if h.logger == nil {
		t.Fatalf("expected default logger to be initialized")
	}
}

func TestTokenHandlerDecryptTokenNilHandler(t *testing.T) {
	var h *TokenHandler
	if _, err := h.DecryptToken(context.Background(), "{}"); err == nil {
		t.Fatalf("expected nil handler error")
	}
}

func TestTokenHandlerDecryptTokenRejectsInvalidExpirationFormat(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	tokenStr := buildEncryptedTokenFromPayload(t, leaf, root, map[string]any{
		"messageExpiration": "not-a-rfc3339-time",
	}, EcV1, "root-1")

	h := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey},
		},
	}

	_, err := h.DecryptToken(context.Background(), tokenStr)
	if err == nil {
		t.Fatalf("expected invalid expiration format error")
	}
	if !strings.Contains(err.Error(), "invalid message expiration format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsExpiredToken(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	tokenStr := buildEncryptedTokenFromPayload(t, leaf, root, map[string]any{
		"messageExpiration": nowWithOffset(-time.Minute).Format(time.RFC3339),
	}, EcV1, "root-1")

	h := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey},
		},
	}

	_, err := h.DecryptToken(context.Background(), tokenStr)
	if err == nil || !strings.Contains(err.Error(), "token has expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenDefaultsExpirationToOneHour(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	tokenStr := buildEncryptedTokenFromPayload(t, leaf, root, map[string]any{
		"paymentMethodType": "CARD",
	}, EcV1, "root-1")

	h := &TokenHandler{
		logger: logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{
			privateKey: leaf,
			rootKeys:   map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey},
		},
	}

	before := time.Now()
	token, err := h.DecryptToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("expected token decryption success: %v", err)
	}

	if token.ExpiresAt.IsZero() {
		t.Fatalf("expected default expiration to be set")
	}
	if !token.ExpiresAt.After(before.Add(50 * time.Minute)) {
		t.Fatalf("expected expiration roughly one hour later, got %s", token.ExpiresAt.Format(time.RFC3339))
	}
	if token.DecryptedAt.IsZero() {
		t.Fatalf("expected decryptedAt to be set")
	}
}

func TestTokenHandlerDecryptAESRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	if _, err := h.decryptAES([]byte("short"), make([]byte, 16)); err == nil {
		t.Fatalf("expected encrypted data too short")
	}

	if _, err := h.decryptAES(make([]byte, 16), make([]byte, 4)); err == nil {
		t.Fatalf("expected invalid key length error")
	}
}

func TestTokenHandlerDecryptAESRejectsBadPadding(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	iv := make([]byte, aes.BlockSize)
	plaintext := []byte("abcdefghijklmnop")
	plaintext[len(plaintext)-1] = 0x07
	plaintext[len(plaintext)-2] = 0x06

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		t.Fatalf("create cipher failed: %v", err)
	}

	encryptedBody := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encryptedBody, plaintext)

	encrypted := make([]byte, 0, len(iv)+len(encryptedBody))
	encrypted = append(encrypted, iv...)
	encrypted = append(encrypted, encryptedBody...)

	if _, err := h.decryptAES(encrypted, key); err == nil {
		t.Fatalf("expected invalid padding to fail")
	}
}

func TestTokenHandlerParseEphemeralPublicKeyRejectsInvalidData(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	if _, err := h.parseEphemeralPublicKey([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("expected short key to fail")
	}
}

func TestTokenHandlerParseEphemeralPublicKeyRejectsInvalidCurvePoint(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	bytesVal := make([]byte, 65)
	bytesVal[0] = 0x04

	if _, err := h.parseEphemeralPublicKey(bytesVal); err == nil {
		t.Fatalf("expected invalid curve point to fail")
	}
}

func TestTokenHandlerPerformECDHRejectsNilPublicKey(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{keyManager: &KeyManager{}, logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if _, err := h.performECDH(nil); err == nil {
		t.Fatalf("expected nil ephemeral public key to fail")
	}
}

func TestTokenHandlerPerformECDHRejectsMissingPrivateKey(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{
		keyManager: &KeyManager{},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{0x01})

	if _, err := h.performECDH(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}); err == nil {
		t.Fatalf("expected missing private key to fail")
	}
}

func TestTokenHandlerPerformECDHRejectsNilCurve(t *testing.T) {
	t.Parallel()

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: newECKeyPair(t)},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	if _, err := h.performECDH(&ecdsa.PublicKey{Curve: nil}); err == nil {
		t.Fatalf("expected nil curve error")
	}
}

func TestTokenHandlerPerformECDHRejectsMissingPrivateScalar(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{0x02})

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}}},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	if _, err := h.performECDH(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}); err == nil {
		t.Fatalf("expected missing private scalar error")
	}
}

func TestTokenHandlerPerformECDHRejectsNilSharedSecret(t *testing.T) {
	t.Parallel()

	curve := nilSharedSecretCurve{}
	recipient := newECKeyPair(t)

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: recipient},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	if _, err := h.performECDH(&ecdsa.PublicKey{Curve: curve, X: recipient.PublicKey.X, Y: recipient.PublicKey.Y}); err == nil {
		t.Fatalf("expected nil shared secret error")
	}
}

func TestTokenHandlerPerformECDHReturnsZeroSharedSecretForZeroXPoint(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()
	pointX := big.NewInt(0)
	pointY := new(big.Int).ModSqrt(curve.Params().B, curve.Params().P)
	if pointY == nil {
		t.Fatalf("unable to compute x=0 point on P-256")
	}

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy},
			D:         big.NewInt(1),
		}},
		logger: logs.NewLogger(logs.LogLevelInfo, false),
	}

	shared, err := h.performECDH(&ecdsa.PublicKey{Curve: curve, X: pointX, Y: pointY})
	if err != nil {
		t.Fatalf("expected shared secret calculation to succeed: %v", err)
	}
	if len(shared) != 0 {
		t.Fatalf("expected zero-length shared secret, got %d", len(shared))
	}
}

type nilSharedSecretCurve struct{}

func (c nilSharedSecretCurve) Params() *elliptic.CurveParams { return elliptic.P256().Params() }

func (c nilSharedSecretCurve) IsOnCurve(x, y *big.Int) bool {
	return true
}

func (c nilSharedSecretCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return elliptic.P256().Add(x1, y1, x2, y2)
}

func (c nilSharedSecretCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return elliptic.P256().Double(x1, y1)
}

func (c nilSharedSecretCurve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	return nil, nil
}

func (c nilSharedSecretCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return elliptic.P256().ScalarBaseMult(k)
}

func TestTokenHandlerBuildSignatureData(t *testing.T) {
	h := &TokenHandler{}

	enc := EncryptedToken{ProtocolVersion: string(EcV1), SignedMessage: SignedMessage{
		EncryptedMessage:   "enc",
		EphemeralPublicKey: "epk",
		Tag:                "tag",
	}}

	v1 := string(h.buildECv1SignatureData(&enc))
	if v1 != "enc.epk.tag.ECv1" {
		t.Fatalf("unexpected ecv1 signature data: %s", v1)
	}

	enc.ProtocolVersion = string(EcV2)
	v2 := string(h.buildECv2SignatureData(&enc))
	if v2 != "enc.epk.tag.ECv2." {
		t.Fatalf("unexpected ecv2 signature data: %s", v2)
	}
}

func TestTokenHandlerBuildSignatureDataRejectsUnsupportedProtocol(t *testing.T) {
	h := &TokenHandler{}
	if _, err := h.buildSignatureData(&EncryptedToken{ProtocolVersion: "ECv3"}); err == nil {
		t.Fatalf("expected unsupported protocol error")
	}
}

func TestTokenHandlerVerifySignatureRejectsMalformedSignature(t *testing.T) {
	root := newECKeyPair(t)
	h := &TokenHandler{
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{rootKeys: map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey}},
	}

	token := &EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   "enc",
			EphemeralPublicKey: "epk",
			Tag:                "tag",
			KeyID:              "root-1",
			Signature:          "@@bad@@",
		},
	}

	if err := h.verifySignature(context.Background(), token); err == nil {
		t.Fatalf("expected malformed signature decode error")
	}
}

func TestTokenHandlerVerifyECDSASignatureRejectsMalformedBytesWithLogger(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if h.verifyECDSASignature(&ecdsa.PublicKey{}, []byte("data"), []byte("bad")) {
		t.Fatalf("expected malformed signature to fail")
	}
}

func TestTokenHandlerVerifySignatureRejectsInvalidSignature(t *testing.T) {
	root := newECKeyPair(t)
	wrong := newECKeyPair(t)

	h := &TokenHandler{
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{rootKeys: map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey}},
	}

	token := &EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   "enc",
			EphemeralPublicKey: "epk",
			Tag:                "tag",
			KeyID:              "root-1",
		},
	}
	token.SignedMessage.Signature = encodeSignature(t, wrong, token)

	if err := h.verifySignature(context.Background(), token); err == nil {
		t.Fatalf("expected signature verification failure")
	}
}

func TestTokenHandlerVerifySignatureRejectsUnsupportedProtocol(t *testing.T) {
	root := newECKeyPair(t)
	h := &TokenHandler{
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
		keyManager: &KeyManager{rootKeys: map[string]*ecdsa.PublicKey{"root-1": &root.PublicKey}},
	}

	if err := h.verifySignature(context.Background(), &EncryptedToken{
		ProtocolVersion: "ECv3",
		SignedMessage: SignedMessage{
			EncryptedMessage:   "e",
			EphemeralPublicKey: "",
			Tag:                "",
			KeyID:              "root-1",
			Signature:          "",
		},
	}); err == nil {
		t.Fatalf("expected unsupported protocol error")
	}
}

func TestTokenHandlerVerifySignatureRefreshMissingRootKeyAndStillMissing(t *testing.T) {
	root := newECKeyPair(t)
	replacement := newECKeyPair(t)
	replacementResponse := rootKeysJSONResponse(t, "other", replacement)

	h := &TokenHandler{
		keyManager: &KeyManager{
			config:     &Config{Environment: EnvironmentSandbox},
			rootKeys:   map[string]*ecdsa.PublicKey{},
			httpClient: &http.Client{},
		},
	}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, replacementResponse), nil
	}), func() {
		token := &EncryptedToken{
			ProtocolVersion: string(EcV1),
			SignedMessage: SignedMessage{
				EncryptedMessage:   "e",
				EphemeralPublicKey: "",
				Tag:                "",
				KeyID:              "root-1",
				Signature:          encodeSignature(t, root, &EncryptedToken{ProtocolVersion: string(EcV1), SignedMessage: SignedMessage{EncryptedMessage: "e", EphemeralPublicKey: "", Tag: "", KeyID: "root-1"}}),
			},
		}

		if err := h.verifySignature(context.Background(), token); err == nil {
			t.Fatalf("expected root key missing after refresh")
		}
	})
}

func TestTokenHandlerVerifySignatureRefreshesMissingRootKey(t *testing.T) {
	rootSigning := newECKeyPair(t)
	rootPubPEM := rootKeysJSONResponse(t, "root-1", rootSigning)

	recipient := newECKeyPair(t)
	enc := &EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage:   SignedMessage{EncryptedMessage: "e", EphemeralPublicKey: "", Tag: "", KeyID: "root-1"},
	}
	enc.SignedMessage.Signature = encodeSignature(t, rootSigning, enc)

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]*ecdsa.PublicKey{},
		httpClient: &http.Client{},
		privateKey: recipient,
	}
	h := &TokenHandler{config: &Config{}, keyManager: km}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootPubPEM), nil
	}), func() {
		if err := h.verifySignature(context.Background(), enc); err != nil {
			t.Fatalf("expected missing root key to refresh and succeed: %v", err)
		}
	})
}

func TestTokenHandlerVerifySignatureRefreshFailure(t *testing.T) {
	rootSigning := newECKeyPair(t)
	enc := &EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage:   SignedMessage{EncryptedMessage: "e", EphemeralPublicKey: "", Tag: "", KeyID: "unknown"},
	}
	enc.SignedMessage.Signature = encodeSignature(t, rootSigning, enc)

	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]*ecdsa.PublicKey{},
		httpClient: &http.Client{},
	}
	h := &TokenHandler{config: &Config{}, keyManager: km}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusInternalServerError, `{"keys":[]}`), nil
	}), func() {
		if err := h.verifySignature(context.Background(), enc); err == nil {
			t.Fatalf("expected refresh failure error")
		}
	})
}

func TestTokenHandlerDecryptDataRejectsMACMismatch(t *testing.T) {
	recipient := newECKeyPair(t)
	curve := elliptic.P256()
	ephemeral, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key generation failed: %v", err)
	}
	epk := elliptic.Marshal(curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: recipient},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	_, err = h.decryptData(&EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(epk),
			Tag:                base64.StdEncoding.EncodeToString([]byte("wrong-tag")),
		},
	})
	if err == nil {
		t.Fatalf("expected MAC mismatch error")
	}
}

func TestTokenHandlerDecryptDataRejectsKeyDerivationFailure(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()

	// Use a valid P-256 point with X=0 so that recipient scalar=1 yields sharedSecret.X == 0.
	pointX := big.NewInt(0)
	pointY := new(big.Int).ModSqrt(curve.Params().B, curve.Params().P)
	if pointY == nil {
		t.Fatalf("unexpected failure deriving valid point for x=0")
	}

	recipient := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     curve.Params().Gx,
			Y:     curve.Params().Gy,
		},
		D: big.NewInt(1),
	}

	ephemeralPublicKey := elliptic.Marshal(curve, pointX, pointY)
	ephemeralPublicKeyStr := base64.StdEncoding.EncodeToString(ephemeralPublicKey)

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: recipient},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	decodedPoint, parseErr := base64.StdEncoding.DecodeString(ephemeralPublicKeyStr)
	if parseErr != nil {
		t.Fatalf("base64 decode ephemeral key failed: %v", parseErr)
	}

	parsedEphemeralPublicKey, err := h.parseEphemeralPublicKey(decodedPoint)
	if err != nil {
		t.Fatalf("unexpected ephemeral key parse error: %v", err)
	}

	sharedSecret, err := h.performECDH(parsedEphemeralPublicKey)
	if err != nil {
		t.Fatalf("unexpected ecdh error: %v", err)
	}
	if len(sharedSecret) != 0 {
		t.Fatalf("expected zero-length shared secret, got %d", len(sharedSecret))
	}

	_, _, deriveErr := h.deriveKeys(sharedSecret, decodedPoint)
	if deriveErr == nil {
		t.Fatalf("expected key derivation to fail with empty shared secret")
	}

	_, err = h.decryptData(&EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize*2)),
			EphemeralPublicKey: ephemeralPublicKeyStr,
			Tag:                "",
			KeyID:              "root-1",
		},
	})
	if err == nil {
		t.Fatalf("expected key derivation failure")
	}

	if !strings.Contains(err.Error(), "key derivation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenHandlerDecryptDataRejectsMissingPrivateKeyForECDH(t *testing.T) {
	curve := elliptic.P256()
	ephemeral, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	epk := elliptic.Marshal(curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	h := &TokenHandler{
		keyManager: &KeyManager{},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	if _, err := h.decryptData(&EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(make([]byte, 16)),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(epk),
			Tag:                base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}); err == nil || !strings.Contains(err.Error(), "ECDH failed") {
		t.Fatalf("expected ecdh failure, got %v", err)
	}
}

func TestTokenHandlerDecryptDataRejectsShortCiphertextAndReturnsAESError(t *testing.T) {
	root := newECKeyPair(t)
	recipient := newECKeyPair(t)
	curve := elliptic.P256()
	ephemeral, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	curveBytes := elliptic.Marshal(curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: recipient},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	sharedSecret, err := h.performECDH(&ecdsa.PublicKey{Curve: curve, X: ephemeral.PublicKey.X, Y: ephemeral.PublicKey.Y})
	if err != nil {
		t.Fatalf("perform ecdh: %v", err)
	}
	encryptionKey, macKey, err := h.deriveKeys(sharedSecret, curveBytes)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	encryptedMessage := []byte("small-msg")
	hmacCtx := hmac.New(sha256.New, macKey)
	hmacCtx.Write(encryptedMessage)
	tag := base64.StdEncoding.EncodeToString(hmacCtx.Sum(nil))

	if _, err := h.decryptData(&EncryptedToken{
		ProtocolVersion: string(EcV1),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(encryptedMessage),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(curveBytes),
			Tag:                tag,
			KeyID:              root.PublicKey.X.String(),
		},
	}); err == nil || !strings.Contains(err.Error(), "AES decryption failed") {
		t.Fatalf("expected aes decryption failure, got %v", err)
	}

	if _, err := h.decryptAES(make([]byte, aes.BlockSize), encryptionKey); err == nil {
		t.Fatalf("expected invalid ciphertext length when decrypting")
	}
}

func TestTokenHandlerDecryptDataRejectsInvalidEncryptedMessageBase64(t *testing.T) {
	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: newECKeyPair(t)},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	_, err := h.decryptData(&EncryptedToken{SignedMessage: SignedMessage{
		EncryptedMessage:   "%% not base64 %%",
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 65)),
		Tag:                base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}})
	if err == nil {
		t.Fatalf("expected encrypted message decode failure")
	}

	if !strings.Contains(err.Error(), "failed to decode encrypted message") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenHandlerDecryptDataRejectsInvalidEphemeralPublicKeyBase64(t *testing.T) {
	h := &TokenHandler{
		keyManager: &KeyManager{privateKey: newECKeyPair(t)},
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}

	_, err := h.decryptData(&EncryptedToken{SignedMessage: SignedMessage{
		EncryptedMessage:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
		EphemeralPublicKey: "@@@",
		Tag:                base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}})
	if err == nil {
		t.Fatalf("expected ephemeral public key decode failure")
	}

	if !strings.Contains(err.Error(), "failed to decode ephemeral public key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenHandlerVerifyMACRejectsInvalidBase64(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if err := h.verifyMAC([]byte("abc"), []byte("key"), "%%%"); err == nil {
		t.Fatalf("expected base64 error")
	}

	if err := h.verifyMAC([]byte("abc"), []byte(""), "dGVzdA=="); err == nil {
		t.Fatalf("expected empty mac key error")
	}
}

func TestTokenHandlerVerifyMACRejectsMismatch(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if err := h.verifyMAC([]byte("abc"), []byte("key-123"), base64.StdEncoding.EncodeToString([]byte("not-equal"))); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestTokenHandlerDecryptAESRejectsInvalidCiphertextLength(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if _, err := h.decryptAES(make([]byte, aes.BlockSize+1), make([]byte, 32)); err == nil {
		t.Fatalf("expected invalid ciphertext length error")
	}
}

func TestTokenHandlerDecryptAESRejectsInvalidCipherKeySize(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if _, err := h.decryptAES(make([]byte, aes.BlockSize*2), make([]byte, 33)); err == nil {
		t.Fatalf("expected invalid cipher key size error")
	}
}

func TestTokenHandlerDecryptAESPropagatesCipherCreationError(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	oldNewAESCipher := newAESCipher
	newAESCipher = func(_ []byte) (cipher.Block, error) {
		return nil, errors.New("cipher create failed")
	}
	defer func() {
		newAESCipher = oldNewAESCipher
	}()

	if _, err := h.decryptAES(make([]byte, aes.BlockSize*2), make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "failed to create AES cipher") {
		t.Fatalf("expected aes cipher creation failure, got %v", err)
	}
}

func TestTokenHandlerRemovePKCS7PaddingRejectsEmptyData(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	if _, err := h.removePKCS7Padding([]byte{}); err == nil {
		t.Fatalf("expected empty data padding error")
	}
}

func TestTokenHandlerRemovePKCS7PaddingRejectsInvalidLengthMarker(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}

	data := make([]byte, aes.BlockSize)
	data[len(data)-1] = 0
	if _, err := h.removePKCS7Padding(data); err == nil {
		t.Fatalf("expected invalid padding length marker error")
	}
}

func TestTokenHandlerDeriveKeysRejectsMissingInputs(t *testing.T) {
	h := &TokenHandler{}
	if _, _, err := h.deriveKeys(nil, []byte("x")); err == nil {
		t.Fatalf("expected shared secret empty error")
	}
	if _, _, err := h.deriveKeys([]byte("x"), nil); err == nil {
		t.Fatalf("expected ephemeral key empty error")
	}
}

func TestTokenHandlerValidateSignatureRejectsExpiredMessage(t *testing.T) {
	h := &TokenHandler{}

	expired := nowWithOffset(-time.Hour).Format(time.RFC3339)
	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: expired}); err == nil {
		t.Fatalf("expected expired message validation error")
	}
}

func ecdsaSignatureASN1(t *testing.T, private *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()

	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, private, h[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}

	sig, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal ecdsa signature: %v", err)
	}

	return sig
}

func encodeSignature(t *testing.T, private *ecdsa.PrivateKey, token *EncryptedToken) string {
	t.Helper()
	if private == nil || token == nil {
		t.Fatalf("invalid signature inputs")
	}

	th := &TokenHandler{}
	data, err := th.buildSignatureData(token)
	if err != nil {
		t.Fatalf("build signature data: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ecdsaSignatureASN1(t, private, data))
}

func buildEncryptedTokenFromPayload(t *testing.T, recipient *ecdsa.PrivateKey, root *ecdsa.PrivateKey, payload map[string]any, protocol TokenProtocol, keyID string) string {
	t.Helper()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal token payload: %v", err)
	}

	ephemeral := newECKeyPair(t)

	sharedSecretX, _ := recipient.Curve.ScalarMult(ephemeral.PublicKey.X, ephemeral.PublicKey.Y, recipient.D.Bytes())
	if sharedSecretX == nil {
		t.Fatalf("ECDH shared secret is nil")
	}

	ephemeralPublicKey := elliptic.Marshal(elliptic.P256(), ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	h := &TokenHandler{}
	encryptionKey, macKey, err := h.deriveKeys(sharedSecretX.Bytes(), ephemeralPublicKey)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	padLen := aes.BlockSize - (len(payloadBytes) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}

	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plaintext := append(payloadBytes, padding...)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generate iv: %v", err)
	}

	block, err := aes.NewCipher(encryptionKey[:32])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}

	cipherText := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, plaintext)

	encrypted := make([]byte, 0, len(iv)+len(cipherText))
	encrypted = append(encrypted, iv...)
	encrypted = append(encrypted, cipherText...)

	hmacSum := hmac.New(sha256.New, macKey)
	hmacSum.Write(encrypted)
	tag := base64.StdEncoding.EncodeToString(hmacSum.Sum(nil))

	enc := &EncryptedToken{
		ProtocolVersion: string(protocol),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(encrypted),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPublicKey),
			Tag:                tag,
			KeyID:              keyID,
		},
	}
	enc.SignedMessage.Signature = encodeSignature(t, root, enc)

	encoded, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("marshal encrypted token: %v", err)
	}

	return string(encoded)
}

func buildEncryptedTokenFromPayloadBytes(t *testing.T, recipient *ecdsa.PrivateKey, root *ecdsa.PrivateKey, payloadBytes []byte, protocol TokenProtocol, keyID string) string {
	t.Helper()

	ephemeral := newECKeyPair(t)

	sharedSecretX, _ := recipient.Curve.ScalarMult(ephemeral.PublicKey.X, ephemeral.PublicKey.Y, recipient.D.Bytes())
	if sharedSecretX == nil {
		t.Fatalf("ECDH shared secret is nil")
	}

	ephemeralPublicKey := elliptic.Marshal(elliptic.P256(), ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	h := &TokenHandler{}
	encryptionKey, macKey, err := h.deriveKeys(sharedSecretX.Bytes(), ephemeralPublicKey)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	padLen := aes.BlockSize - (len(payloadBytes) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}

	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plaintext := append(payloadBytes, padding...)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generate iv: %v", err)
	}

	block, err := aes.NewCipher(encryptionKey[:32])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}

	cipherText := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, plaintext)

	encrypted := make([]byte, 0, len(iv)+len(cipherText))
	encrypted = append(encrypted, iv...)
	encrypted = append(encrypted, cipherText...)

	hmacSum := hmac.New(sha256.New, macKey)
	hmacSum.Write(encrypted)
	tag := base64.StdEncoding.EncodeToString(hmacSum.Sum(nil))

	enc := &EncryptedToken{
		ProtocolVersion: string(protocol),
		SignedMessage: SignedMessage{
			EncryptedMessage:   base64.StdEncoding.EncodeToString(encrypted),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPublicKey),
			Tag:                tag,
			KeyID:              keyID,
		},
	}
	enc.SignedMessage.Signature = encodeSignature(t, root, enc)

	encoded, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("marshal encrypted token: %v", err)
	}

	return string(encoded)
}
