package payment

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godrealms/go-google-sdk/utils/logs"
)

// --- Public API tests -------------------------------------------------------

func TestTokenHandlerNewRejectsNilDependencies(t *testing.T) {
	if _, err := NewTokenHandler(nil, &KeyManager{}, nil); err == nil {
		t.Fatalf("expected nil config error")
	}
	if _, err := NewTokenHandler(&Config{MerchantID: "m"}, nil, nil); err == nil {
		t.Fatalf("expected nil key manager error")
	}
	h, err := NewTokenHandler(&Config{MerchantID: "m"}, &KeyManager{}, nil)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if h == nil || h.logger == nil {
		t.Fatalf("expected handler with default logger")
	}
}

func TestTokenHandlerDecryptTokenRejectsNilHandler(t *testing.T) {
	var h *TokenHandler
	if _, err := h.DecryptToken(context.Background(), "{}"); err == nil {
		t.Fatalf("expected nil handler error")
	}
}

func TestTokenHandlerDecryptTokenRejectsMissingKeyManager(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false)}
	_, err := h.DecryptToken(context.Background(), `{"protocolVersion":"ECv1"}`)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected uninitialized error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsInvalidJSON(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false), keyManager: &KeyManager{}}
	if _, err := h.DecryptToken(context.Background(), "{not json"); err == nil {
		t.Fatalf("expected JSON parse error")
	}
}

func TestTokenHandlerDecryptTokenRejectsUnsupportedProtocol(t *testing.T) {
	h := &TokenHandler{logger: logs.NewLogger(logs.LogLevelInfo, false), keyManager: &KeyManager{}}
	if _, err := h.DecryptToken(context.Background(), `{"protocolVersion":"ECv3"}`); err == nil {
		t.Fatalf("expected unsupported protocol error")
	}
}

func TestTokenHandlerDecryptTokenECv1RoundTrip(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)

	payload := map[string]any{
		"paymentMethod":     "CARD",
		"paymentMethodType": "CARD",
		"messageId":         "msg-123",
		"messageExpiration": msExp(time.Now().Add(time.Hour)),
		"paymentMethodDetails": map[string]any{
			"pan":             "4111111111111111",
			"expirationMonth": 12,
			"expirationYear":  2030,
		},
	}
	tokenStr := buildECv1Token(t, leaf, root, "merchant-id", payload)

	h := newTestHandler(t, "merchant-id", leaf, root)

	decrypted, err := h.DecryptToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("expected decryption to succeed: %v", err)
	}
	if decrypted.MessageID != "msg-123" {
		t.Fatalf("unexpected MessageID: %s", decrypted.MessageID)
	}
	if decrypted.PaymentMethodDetails.PAN != "4111111111111111" {
		t.Fatalf("unexpected PAN: %s", decrypted.PaymentMethodDetails.PAN)
	}
	if decrypted.DecryptedAt.IsZero() {
		t.Fatalf("expected DecryptedAt to be set")
	}
}

func TestTokenHandlerDecryptTokenECv1RejectsWrongSignature(t *testing.T) {
	root := newECKeyPair(t)
	wrongRoot := newECKeyPair(t)
	leaf := newECKeyPair(t)

	tokenStr := buildECv1Token(t, leaf, wrongRoot, "merchant-id", map[string]any{"paymentMethod": "CARD"})
	h := newTestHandler(t, "merchant-id", leaf, root)

	if _, err := h.DecryptToken(context.Background(), tokenStr); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature verification failure, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenECv1RejectsWrongMerchant(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)

	tokenStr := buildECv1Token(t, leaf, root, "other-merchant", map[string]any{"paymentMethod": "CARD"})
	h := newTestHandler(t, "merchant-id", leaf, root)

	if _, err := h.DecryptToken(context.Background(), tokenStr); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected merchant mismatch to fail signature, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsExpired(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	tokenStr := buildECv1Token(t, leaf, root, "m", map[string]any{
		"paymentMethod":     "CARD",
		"messageExpiration": msExp(time.Now().Add(-time.Minute)),
	})
	h := newTestHandler(t, "m", leaf, root)

	if _, err := h.DecryptToken(context.Background(), tokenStr); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenECv2RoundTrip(t *testing.T) {
	root := newECKeyPair(t)
	intermediate := newECKeyPair(t)
	leaf := newECKeyPair(t)

	payload := map[string]any{
		"paymentMethod":     "CARD",
		"messageId":         "ecv2-msg",
		"messageExpiration": msExp(time.Now().Add(time.Hour)),
	}
	tokenStr := buildECv2Token(t, leaf, intermediate, root, "merchant-id", payload, msExp(time.Now().Add(time.Hour)))
	h := newTestHandler(t, "merchant-id", leaf, root)

	decrypted, err := h.DecryptToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("expected ECv2 decrypt success: %v", err)
	}
	if decrypted.MessageID != "ecv2-msg" {
		t.Fatalf("unexpected messageId: %s", decrypted.MessageID)
	}
}

func TestTokenHandlerDecryptTokenECv2RejectsExpiredIntermediate(t *testing.T) {
	root := newECKeyPair(t)
	intermediate := newECKeyPair(t)
	leaf := newECKeyPair(t)

	tokenStr := buildECv2Token(t, leaf, intermediate, root, "m", map[string]any{"paymentMethod": "CARD"}, msExp(time.Now().Add(-time.Minute)))
	h := newTestHandler(t, "m", leaf, root)

	if _, err := h.DecryptToken(context.Background(), tokenStr); err == nil || !strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("expected intermediate expiration error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenECv2RejectsMissingIntermediate(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	h := newTestHandler(t, "m", leaf, root)
	raw, _ := json.Marshal(EncryptedToken{ProtocolVersion: "ECv2", Signature: "AA==", SignedMessage: "{}"})
	if _, err := h.DecryptToken(context.Background(), string(raw)); err == nil || !strings.Contains(err.Error(), "intermediateSigningKey") {
		t.Fatalf("expected missing intermediate error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenRejectsMissingMessageExpiration(t *testing.T) {
	root := newECKeyPair(t)
	leaf := newECKeyPair(t)
	tokenStr := buildECv1Token(t, leaf, root, "m", map[string]any{"paymentMethod": "CARD"})
	h := newTestHandler(t, "m", leaf, root)

	_, err := h.DecryptToken(context.Background(), tokenStr)
	if err == nil || !strings.Contains(err.Error(), "messageExpiration") {
		t.Fatalf("expected missing messageExpiration error, got %v", err)
	}
}

func TestTokenHandlerDecryptTokenECv2RejectsMissingIntermediateExpiration(t *testing.T) {
	root := newECKeyPair(t)
	intermediate := newECKeyPair(t)
	leaf := newECKeyPair(t)

	tokenStr := buildECv2Token(t, leaf, intermediate, root, "m", map[string]any{
		"paymentMethod":     "CARD",
		"messageExpiration": msExp(time.Now().Add(time.Hour)),
	}, "")
	h := newTestHandler(t, "m", leaf, root)

	_, err := h.DecryptToken(context.Background(), tokenStr)
	if err == nil || !strings.Contains(err.Error(), "keyExpiration") {
		t.Fatalf("expected missing intermediate keyExpiration error, got %v", err)
	}
}

// --- Health / ValidateSignature ---------------------------------------------

func TestTokenHandlerValidateSignature(t *testing.T) {
	h := &TokenHandler{}
	if err := h.ValidateSignature(context.Background(), nil); err == nil {
		t.Fatalf("expected nil token error")
	}
	if err := h.ValidateSignature(context.Background(), &PaymentToken{}); err != nil {
		t.Fatalf("expected empty expiration to pass: %v", err)
	}
	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: "bad"}); err == nil {
		t.Fatalf("expected invalid expiration to fail")
	}
	expired := msExp(time.Now().Add(-time.Minute))
	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: expired}); err == nil {
		t.Fatalf("expected expired to fail")
	}
	future := msExp(time.Now().Add(time.Hour))
	if err := h.ValidateSignature(context.Background(), &PaymentToken{MessageExpiration: future}); err != nil {
		t.Fatalf("expected future expiration to pass: %v", err)
	}
}

func TestTokenHandlerHealth(t *testing.T) {
	h := &TokenHandler{}
	if err := h.Health(context.Background()); err == nil {
		t.Fatalf("expected missing key manager error")
	}
	leaf := newECKeyPair(t)
	km := &KeyManager{
		privateKey: leaf,
		rootKeys:   map[string]rootKey{"k": {PublicKey: &leaf.PublicKey}},
	}
	h.keyManager = km
	if err := h.Health(context.Background()); err != nil {
		t.Fatalf("expected healthy, got %v", err)
	}
}

// --- Package-level helper tests ---------------------------------------------

func TestParseECDSASignatureFormats(t *testing.T) {
	priv := newECKeyPair(t)
	data := []byte("msg")
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(raw[32-len(rb):32], rb)
	copy(raw[64-len(sb):64], sb)
	if _, _, err := parseECDSASignature(raw); err != nil {
		t.Fatalf("expected raw parse, got %v", err)
	}

	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, _, err := parseECDSASignature(der); err != nil {
		t.Fatalf("expected DER parse, got %v", err)
	}

	zeros, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(0)})
	if _, _, err := parseECDSASignature(zeros); err == nil {
		t.Fatalf("expected zero-value rejection")
	}
	if _, _, err := parseECDSASignature([]byte("bad")); err == nil {
		t.Fatalf("expected bad signature rejection")
	}
}

func TestToLengthValue(t *testing.T) {
	got := toLengthValue("Google")
	if len(got) != 4+6 {
		t.Fatalf("unexpected length: %d", len(got))
	}
	if got[0] != 0x06 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("unexpected little-endian prefix: %x", got[:4])
	}
	if string(got[4:]) != "Google" {
		t.Fatalf("unexpected value: %s", string(got[4:]))
	}
}

func TestSignatureDataECv1Format(t *testing.T) {
	data := signatureDataECv1("merchant:m", "signed-message")
	// Expected: len("Google") || "Google" || len("merchant:m") || "merchant:m" || len("ECv1") || "ECv1" || len(signedMessage) || signedMessage
	want := append([]byte{}, toLengthValue("Google")...)
	want = append(want, toLengthValue("merchant:m")...)
	want = append(want, toLengthValue("ECv1")...)
	want = append(want, toLengthValue("signed-message")...)
	if string(data) != string(want) {
		t.Fatalf("signature data mismatch")
	}
}

func TestDeriveKeysRejectsEmptyInputs(t *testing.T) {
	if _, _, err := deriveKeys(nil, []byte("x")); err == nil {
		t.Fatalf("expected empty shared secret error")
	}
	if _, _, err := deriveKeys([]byte("x"), nil); err == nil {
		t.Fatalf("expected empty ephemeral key error")
	}
}

func TestDecryptAESCTRRejectsShortKey(t *testing.T) {
	if _, err := decryptAESCTR(make([]byte, 16), make([]byte, 4)); err == nil {
		t.Fatalf("expected short key error")
	}
}

func TestVerifyMACDetectsTampering(t *testing.T) {
	key := []byte("mac-key")
	ct := []byte("ciphertext")
	h := hmac.New(sha256.New, key)
	h.Write(ct)
	good := h.Sum(nil)
	if err := verifyMAC(ct, key, good); err != nil {
		t.Fatalf("expected verify success: %v", err)
	}
	if err := verifyMAC(ct, key, append([]byte{}, good[:len(good)-1]...)); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestParseUncompressedP256Rejections(t *testing.T) {
	if _, err := parseUncompressedP256([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("expected short key error")
	}
	bad := make([]byte, 65)
	bad[0] = 0x04
	if _, err := parseUncompressedP256(bad); err == nil {
		t.Fatalf("expected off-curve error")
	}
}

func TestParseMsTimestamp(t *testing.T) {
	if _, err := parseMsTimestamp("1700000000000"); err != nil {
		t.Fatalf("ms timestamp: %v", err)
	}
	if _, err := parseMsTimestamp(time.Now().Format(time.RFC3339)); err != nil {
		t.Fatalf("rfc3339: %v", err)
	}
	if _, err := parseMsTimestamp("not-a-time"); err == nil {
		t.Fatalf("expected error for junk")
	}
}

func TestTokenHandlerRecipientID(t *testing.T) {
	var h *TokenHandler
	h = &TokenHandler{}
	if h.recipientID() != "merchant:" {
		t.Fatalf("expected nil config to produce merchant:")
	}
	h.config = &Config{MerchantID: "abc"}
	if h.recipientID() != "merchant:abc" {
		t.Fatalf("unexpected recipient id: %s", h.recipientID())
	}
}

func TestCollectRootKeysRefreshesWhenEmpty(t *testing.T) {
	root := newECKeyPair(t)
	km := &KeyManager{
		config:     &Config{Environment: EnvironmentSandbox},
		rootKeys:   map[string]rootKey{},
		httpClient: &http.Client{},
	}
	h := &TokenHandler{keyManager: km, logger: logs.NewLogger(logs.LogLevelInfo, false)}

	withStubbedDefaultTransport(t, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return responseWithBody(t, http.StatusOK, rootKeysJSONResponse(t, "r", root)), nil
	}), func() {
		keys, err := h.collectRootKeys(context.Background(), EcV1)
		if err != nil {
			t.Fatalf("expected refresh success: %v", err)
		}
		if len(keys) == 0 {
			t.Fatalf("expected at least one key")
		}
	})
}

// --- Test helpers -----------------------------------------------------------

func newTestHandler(t *testing.T, merchantID string, leaf, root *ecdsa.PrivateKey) *TokenHandler {
	t.Helper()
	km := &KeyManager{
		privateKey: leaf,
		rootKeys:   map[string]rootKey{"root-1": {PublicKey: &root.PublicKey}},
	}
	return &TokenHandler{
		config:     &Config{MerchantID: merchantID},
		keyManager: km,
		logger:     logs.NewLogger(logs.LogLevelInfo, false),
	}
}

// msExp encodes t as milliseconds since epoch, as Google delivers expirations.
func msExp(t time.Time) string {
	return strconv.FormatInt(t.UnixMilli(), 10)
}

// encryptForMerchant builds a spec-compliant signedMessage payload: encrypts
// payload bytes with AES-256-CTR using HKDF-derived keys, returns the JSON
// string that should go into EncryptedToken.SignedMessage.
func encryptForMerchant(t *testing.T, recipientPub *ecdsa.PublicKey, recipientScalarFrom *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()

	ephemeral := newECKeyPair(t)

	// ECDH: ephemeral private * recipient public (matches what the SDK does
	// on the other side: recipient private * ephemeral public).
	sharedX, _ := recipientPub.Curve.ScalarMult(recipientPub.X, recipientPub.Y, ephemeral.D.Bytes())
	if sharedX == nil {
		t.Fatalf("ECDH shared secret nil")
	}
	secret := make([]byte, 32)
	xb := sharedX.Bytes()
	copy(secret[32-len(xb):], xb)

	ephemeralPubBytes := elliptic.Marshal(elliptic.P256(), ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	symKey, macKey, err := deriveKeys(secret, ephemeralPubBytes)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	// AES-256-CTR encrypt with zero IV.
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	ciphertext := make([]byte, len(payload))
	cipher.NewCTR(block, make([]byte, block.BlockSize())).XORKeyStream(ciphertext, payload)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext)

	msg := SignedMessagePayload{
		EncryptedMessage:   base64.StdEncoding.EncodeToString(ciphertext),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPubBytes),
		Tag:                base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}
	_ = recipientScalarFrom // reserved for future negative tests
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal signed message: %v", err)
	}
	return string(b)
}

// signData signs data with private key and returns ASN.1 DER base64-encoded.
func signData(t *testing.T, priv *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// buildECv1Token produces a full ECv1 token string, encrypting payload for
// recipient (the merchant's private key) and signing with root.
func buildECv1Token(t *testing.T, recipient, root *ecdsa.PrivateKey, merchantID string, payload map[string]any) string {
	t.Helper()
	plainBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signedMessage := encryptForMerchant(t, &recipient.PublicKey, recipient, plainBytes)

	sigData := signatureDataECv1("merchant:"+merchantID, signedMessage)
	signature := signData(t, root, sigData)

	tok := EncryptedToken{
		ProtocolVersion: "ECv1",
		Signature:       signature,
		SignedMessage:   signedMessage,
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return string(raw)
}

// buildECv2Token produces an ECv2 token: intermediate signing key signed by
// root, outer signedMessage signed by intermediate.
func buildECv2Token(t *testing.T, recipient, intermediate, root *ecdsa.PrivateKey, merchantID string, payload map[string]any, intermediateExpiration string) string {
	t.Helper()

	plainBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signedMessage := encryptForMerchant(t, &recipient.PublicKey, recipient, plainBytes)

	intermediatePubDER, err := x509.MarshalPKIXPublicKey(&intermediate.PublicKey)
	if err != nil {
		t.Fatalf("marshal intermediate pub: %v", err)
	}
	intermediateSignedKey := IntermediateSignedKey{
		KeyValue:      base64.StdEncoding.EncodeToString(intermediatePubDER),
		KeyExpiration: intermediateExpiration,
	}
	signedKeyBytes, err := json.Marshal(intermediateSignedKey)
	if err != nil {
		t.Fatalf("marshal signed key: %v", err)
	}
	signedKeyStr := string(signedKeyBytes)

	intermediateSigData := signatureDataECv2Intermediate(signedKeyStr)
	intermediateSig := signData(t, root, intermediateSigData)

	outerSigData := signatureDataECv2Message("merchant:"+merchantID, signedMessage)
	outerSig := signData(t, intermediate, outerSigData)

	tok := EncryptedToken{
		ProtocolVersion: "ECv2",
		Signature:       outerSig,
		SignedMessage:   signedMessage,
		IntermediateSigningKey: &IntermediateSigningKey{
			SignedKey:  signedKeyStr,
			Signatures: []string{intermediateSig},
		},
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return string(raw)
}
