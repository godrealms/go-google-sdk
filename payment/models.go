package payment

import (
	"encoding/json"
	"time"
)

// EncryptedToken 加密Token结构
type EncryptedToken struct {
	ProtocolVersion string        `json:"protocolVersion"`
	Signature       string        `json:"signature"`
	SignedMessage   SignedMessage `json:"signedMessage"`
}

// SignedMessage 签名消息结构
type SignedMessage struct {
	EncryptedMessage   string `json:"encryptedMessage"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Tag                string `json:"tag"`
	KeyID              string `json:"keyId,omitempty"`
	Signature          string `json:"signature,omitempty"`
}

// PaymentToken 支付Token结构
type PaymentToken struct {
	// 基本信息
	MessageID                string `json:"messageId"`
	MessageExpiration        string `json:"messageExpiration"`
	PaymentMethod            string `json:"paymentMethod"`
	PaymentMethodType        string `json:"paymentMethodType"`
	PaymentMethodDescription string `json:"paymentMethodDescription"`

	// 网络信息
	PaymentNetwork string `json:"paymentNetwork,omitempty"`

	// 卡片信息
	PaymentMethodDetails CardDetails `json:"paymentMethodDetails"`

	// 3DS信息
	AuthenticationMethod string `json:"authenticationMethod,omitempty"`
	CryptogramType       string `json:"cryptogramType,omitempty"`
	Cryptogram           string `json:"cryptogram,omitempty"`
	EciIndicator         string `json:"eciIndicator,omitempty"`

	// 内部字段
	ExpiresAt   time.Time `json:"-"`
	DecryptedAt time.Time `json:"-"`
}

// CardDetails 卡片详情
type CardDetails struct {
	// PAN信息
	PAN             string `json:"pan,omitempty"`
	ExpirationMonth int    `json:"expirationMonth,omitempty"`
	ExpirationYear  int    `json:"expirationYear,omitempty"`

	// 持卡人信息
	CardholderName string `json:"cardholderName,omitempty"`

	// 账单地址
	BillingAddress *BillingAddress `json:"billingAddress,omitempty"`

	// 其他信息
	CardClass   string `json:"cardClass,omitempty"`
	CardDetails string `json:"cardDetails,omitempty"`
}

// BillingAddress 账单地址
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

// PaymentMethodInfo 支付方法信息
type PaymentMethodInfo struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Network     string      `json:"network"`
	Details     CardDetails `json:"details"`
}

// TokenProtocol Token协议类型
type TokenProtocol string

const (
	EcV1 TokenProtocol = "ECv1"
	EcV2 TokenProtocol = "ECv2"
)

// String 实现Stringer接口
func (t TokenProtocol) String() string {
	return string(t)
}

// IsValid 验证协议版本是否有效
func (t TokenProtocol) IsValid() bool {
	return t == EcV1 || t == EcV2
}

// MarshalJSON 自定义JSON序列化
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

// UnmarshalJSON 自定义JSON反序列化
func (pt *PaymentToken) UnmarshalJSON(data []byte) error {
	type Alias PaymentToken
	aux := &struct {
		*Alias
		ExpiresAt   string `json:"expiresAt"`
		DecryptedAt string `json:"decryptedAt"`
	}{
		Alias: (*Alias)(pt),
	}

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

// IsExpired 检查Token是否过期
func (pt *PaymentToken) IsExpired() bool {
	if pt.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(pt.ExpiresAt)
}

// GetCardLast4 获取卡号后4位
func (pt *PaymentToken) GetCardLast4() string {
	if len(pt.PaymentMethodDetails.PAN) >= 4 {
		return pt.PaymentMethodDetails.PAN[len(pt.PaymentMethodDetails.PAN)-4:]
	}
	return ""
}

// GetCardBrand 获取卡品牌
func (pt *PaymentToken) GetCardBrand() string {
	return pt.PaymentNetwork
}
