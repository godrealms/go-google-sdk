package publisher

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/androidpublisher/v3"
	"io"
	"net/http"
	"os"
)

// NewClient Google客户端
func NewClient(config any) (*http.Client, error) {
	var jsonKey []byte
	var err error
	var client *http.Client

	switch config.(type) {
	case string:
		// 读取服务账号 JSON 文件
		jsonKey, err = os.ReadFile(config.(string))
		if err != nil {
			return nil, err
		}
	case []byte:
		jsonKey = config.([]byte)
	case OAuth2, *OAuth2:
		jsonKey, err = json.Marshal(config)
		if err != nil {
			return nil, err
		}
	case io.Reader:
		jsonKey, err = io.ReadAll(config.(io.Reader))
		if err != nil {
			return nil, err
		}
	default:
		ctx := context.Background()
		client, err = google.DefaultClient(ctx, androidpublisher.AndroidpublisherScope)
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	// 使用 JSON 密钥创建 Google OAuth2 凭据
	credentials, err := google.CredentialsFromJSON(context.Background(), jsonKey, androidpublisher.AndroidpublisherScope)
	if err != nil {
		return nil, err
	}

	// 使用 TokenSource 创建 HTTP 客户端
	client = oauth2.NewClient(context.Background(), credentials.TokenSource)
	return client, nil
}
