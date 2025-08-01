package publisher

type Config struct {
	ProjectID      string `json:",omitempty"` // 项目ID
	SubscriptionID string `json:",omitempty"` // 订阅ID
	JsonKey        string `json:",omitempty"` // JsonKey路径地址
}

type OAuth2 struct {
	Type                    string `json:"type"`
	ProjectId               string `json:"project_id"`
	PrivateKeyId            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientId                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
}
