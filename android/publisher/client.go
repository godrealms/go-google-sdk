package publisher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/androidpublisher/v3"
)

// NewHTTPClient creates an HTTP client from various credential sources.
// Accepts a string path, []byte JSON, OAuth2 struct, io.Reader, or nil for ADC.
func NewHTTPClient(ctx context.Context, config any) (*http.Client, error) {
	var jsonKey []byte
	var err error

	switch v := config.(type) {
	case string:
		jsonKey, err = os.ReadFile(v)
		if err != nil {
			return nil, err
		}
	case []byte:
		jsonKey = v
	case OAuth2, *OAuth2:
		jsonKey, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	case io.Reader:
		jsonKey, err = io.ReadAll(v)
		if err != nil {
			return nil, err
		}
	default:
		return google.DefaultClient(ctx, androidpublisher.AndroidpublisherScope)
	}

	credentials, err := google.CredentialsFromJSON(ctx, jsonKey, androidpublisher.AndroidpublisherScope)
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, credentials.TokenSource), nil
}
