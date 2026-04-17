package payment

import (
	"encoding/json"
	"time"
)

// EncryptedToken mirrors the wire format Google Pay delivers to merchants.
//
// ECv1:
//
//	{
//	  "protocolVersion": "ECv1",
//	  "signature": "<base64>",
//	  "signedMessage": "<json-string>"
//	}
//
// ECv2 additionally includes an intermediateSigningKey block that chains the
// outer signature to Google's long-lived root keys.
type EncryptedToken struct {
	ProtocolVersion       string                 `json:"protocolVersion"`
	Signature             string                 `json:"signature"`
	SignedMessage         string                 `json:"signedMessage"`
	IntermediateSigningKey *IntermediateSigningKey `json:"intermediateSigningKey,omitempty"`
}

// IntermediateSigningKey wraps the ECv2 ephemeral signing key that Google
// rotates periodically. SignedKey is itself a JSON-encoded string so that the
// byte-exact value can be signed.
type IntermediateSigningKey struct {
	SignedKey  string   `json:"signedKey"`
	Signatures []string `json:"signatures"`
}

// IntermediateSignedKey is the decoded form of IntermediateSigningKey.SignedKey.
// KeyValue is the base64-encoded ASN.1 SubjectPublicKeyInfo of the intermediate
// ECDSA key; KeyExpiration is milliseconds since the Unix epoch encoded as a
// string (as Google delivers it).
type IntermediateSignedKey struct {
	KeyValue      string `json:"keyValue"`
	KeyExpiration string `json:"keyExpiration"`
}

// SignedMessagePayload is the decoded form of EncryptedToken.SignedMessage.
// All three fields are base64-encoded binary blobs.
type SignedMessagePayload struct {
	EncryptedMessage   string `json:"encryptedMessage"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Tag                string `json:"tag"`
}

// PaymentToken is the decrypted payload delivered inside a Google Pay token.
type PaymentToken struct {
	MessageID                string      `json:"messageId"`
	MessageExpiration        string      `json:"messageExpiration"`
	PaymentMethod            string      `json:"paymentMethod"`
	PaymentMethodType        string      `json:"paymentMethodType"`
	PaymentMethodDescription string      `json:"paymentMethodDescription"`
	PaymentNetwork           string      `json:"paymentNetwork,omitempty"`
	PaymentMethodDetails     CardDetails `json:"paymentMethodDetails"`

	// 3DS / network tokenisation fields.
	AuthenticationMethod string `json:"authenticationMethod,omitempty"`
	CryptogramType       string `json:"cryptogramType,omitempty"`
	Cryptogram           string `json:"cryptogram,omitempty"`
	EciIndicator         string `json:"eciIndicator,omitempty"`

	// ExpiresAt / DecryptedAt are populated by the SDK after decryption.
	ExpiresAt   time.Time `json:"-"`
	DecryptedAt time.Time `json:"-"`
}

// CardDetails is the nested paymentMethodDetails object.
type CardDetails struct {
	PAN             string `json:"pan,omitempty"`
	ExpirationMonth int    `json:"expirationMonth,omitempty"`
	ExpirationYear  int    `json:"expirationYear,omitempty"`

	CardholderName string `json:"cardholderName,omitempty"`

	BillingAddress *BillingAddress `json:"billingAddress,omitempty"`

	CardClass   string `json:"cardClass,omitempty"`
	CardDetails string `json:"cardDetails,omitempty"`
}

// BillingAddress is the optional billing address embedded in CardDetails.
type BillingAddress struct {
	Name               string `json:"name,omitempty"`
	Address1           string `json:"address1,omitempty"`
	Address2           string `json:"address2,omitempty"`
	Address3           string `json:"address3,omitempty"`
	Locality           string `json:"locality,omitempty"`
	AdministrativeArea string `json:"administrativeArea,omitempty"`
	CountryCode        string `json:"countryCode,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	PhoneNumber        string `json:"phoneNumber,omitempty"`
}

// PaymentMethodInfo is a convenience projection returned by
// Client.GetPaymentMethodInfo.
type PaymentMethodInfo struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Network     string      `json:"network"`
	Details     CardDetails `json:"details"`
}

// TokenProtocol enumerates the supported Google Pay token protocol versions.
type TokenProtocol string

const (
	EcV1 TokenProtocol = "ECv1"
	EcV2 TokenProtocol = "ECv2"
)

// String implements fmt.Stringer.
func (t TokenProtocol) String() string { return string(t) }

// IsValid reports whether the protocol version is one this SDK supports.
func (t TokenProtocol) IsValid() bool { return t == EcV1 || t == EcV2 }

// MarshalJSON serialises the two sdk-populated timestamps as RFC3339.
func (pt *PaymentToken) MarshalJSON() ([]byte, error) {
	type Alias PaymentToken
	return json.Marshal(&struct {
		*Alias
		ExpiresAt   string `json:"expiresAt"`
		DecryptedAt string `json:"decryptedAt"`
	}{
		Alias:       (*Alias)(pt),
		ExpiresAt:   pt.ExpiresAt.Format(time.RFC3339),
		DecryptedAt: pt.DecryptedAt.Format(time.RFC3339),
	})
}

// UnmarshalJSON accepts the sdk-serialised form and parses the RFC3339 fields.
func (pt *PaymentToken) UnmarshalJSON(data []byte) error {
	type Alias PaymentToken
	aux := &struct {
		*Alias
		ExpiresAt   string `json:"expiresAt"`
		DecryptedAt string `json:"decryptedAt"`
	}{Alias: (*Alias)(pt)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, aux.ExpiresAt); err == nil {
			pt.ExpiresAt = t
		}
	}
	if aux.DecryptedAt != "" {
		if t, err := time.Parse(time.RFC3339, aux.DecryptedAt); err == nil {
			pt.DecryptedAt = t
		}
	}
	return nil
}

// IsExpired reports whether the token's ExpiresAt has passed. A zero
// ExpiresAt is treated as "never expires".
func (pt *PaymentToken) IsExpired() bool {
	if pt.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(pt.ExpiresAt)
}

// GetCardLast4 returns the last four digits of the decrypted PAN, or empty
// when the PAN is shorter than four characters.
func (pt *PaymentToken) GetCardLast4() string {
	if len(pt.PaymentMethodDetails.PAN) >= 4 {
		return pt.PaymentMethodDetails.PAN[len(pt.PaymentMethodDetails.PAN)-4:]
	}
	return ""
}

// GetCardBrand returns the paymentNetwork field (VISA / MASTERCARD / ...).
func (pt *PaymentToken) GetCardBrand() string { return pt.PaymentNetwork }
