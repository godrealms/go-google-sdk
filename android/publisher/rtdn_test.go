package publisher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)

type fakePubSubSubscription struct {
	received  bool
	errToRet  error
	callback  func(context.Context, *pubsub.Message)
	callCount int
}

func (s *fakePubSubSubscription) Receive(ctx context.Context, f func(context.Context, *pubsub.Message)) error {
	s.received = true
	s.callCount++

	if f != nil {
		f(ctx, &pubsub.Message{})
	}

	if s.callback != nil {
		s.callback(ctx, &pubsub.Message{})
	}

	return s.errToRet
}

type fakePubSubClient struct {
	projectID      string
	subscriptionID string
	options        []option.ClientOption
	closed         bool
	subscription   *fakePubSubSubscription
}

func (c *fakePubSubClient) Subscription(id string) pubSubSubscription {
	c.subscriptionID = id
	if c.subscription == nil {
		c.subscription = &fakePubSubSubscription{}
	}
	return c.subscription
}

func (c *fakePubSubClient) Close() error {
	c.closed = true
	return nil
}

type nilSubscriptionClient struct{}

func (c *nilSubscriptionClient) Subscription(id string) pubSubSubscription {
	return nil
}

func (c *nilSubscriptionClient) Close() error {
	return nil
}

func TestStartSubscriptionMonitorWithContextValidation(t *testing.T) {
	t.Parallel()

	err := StartSubscriptionMonitorWithContext(context.Background(), nil, func(ctx context.Context, msg *pubsub.Message) {})
	if err == nil {
		t.Fatalf("expected nil config error")
	}
	if err.Error() != "config is nil" {
		t.Fatalf("unexpected config error: %v", err)
	}

	cfg := &Config{ProjectID: "project"}
	err = StartSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {})
	if err == nil {
		t.Fatalf("expected missing subscription id error")
	}
	if err.Error() != "subscription ID is required" {
		t.Fatalf("unexpected subscription id error: %v", err)
	}

	cfg.SubscriptionID = "sub"
	err = StartSubscriptionMonitorWithContext(context.Background(), cfg, nil)
	if err == nil {
		t.Fatalf("expected missing handler error")
	}
	if err.Error() != "message handler is required" {
		t.Fatalf("unexpected handler error: %v", err)
	}

	err = StartSubscriptionMonitorWithContext(context.Background(), &Config{SubscriptionID: "sub"}, func(ctx context.Context, msg *pubsub.Message) {})
	if err == nil {
		t.Fatalf("expected missing project id error")
	}
	if err.Error() != "project ID is required" {
		t.Fatalf("unexpected project id error: %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextWithCredentialFileHint(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "creds.json")
	if err := os.WriteFile(credFile, []byte("{\"type\":\"service_account\"}"), 0o600); err != nil {
		t.Fatalf("create credential file: %v", err)
	}

	cfg := &Config{
		ProjectID:      "test-project",
		SubscriptionID: "test-subscription",
		JsonKey:        credFile,
	}

	if err := StartSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {}); err == nil {
		t.Fatalf("expected error with invalid credentials file")
	}
}

func TestStartSubscriptionMonitorWithContextWithRawCredential(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		ProjectID:      "test-project",
		SubscriptionID: "test-subscription",
		JsonKey:        "{\"type\":\"service_account\"}",
	}

	if err := StartSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {}); err == nil {
		t.Fatalf("expected error with inline credential data")
	}
}

func TestStartSubscriptionMonitorPreservesNoPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartSubscriptionMonitor should not panic: %v", r)
		}
	}()

	StartSubscriptionMonitor(nil, nil)
}

func TestNotificationProcessMethodsNoop(t *testing.T) {
	t.Parallel()

	if err := (&SubscriptionNotification{}).Process(); err != nil {
		t.Fatalf("expected subscription notification process to be no-op")
	}

	if err := (&TestNotification{}).Process(); err != nil {
		t.Fatalf("expected test notification process to be no-op")
	}
}

func TestNotificationUnmarshalForAllVariants(t *testing.T) {
	t.Parallel()

	source := `{
		"version":"1.0",
		"packageName":"com.example.app",
		"eventTimeMillis":1690000000000,
		"oneTimeProductNotification":{
			"version":"1.0",
			"notificationType":1,
			"purchaseToken":"otp-token",
			"sku":"sku-1"
		},
		"subscriptionNotification":{
			"version":"1.0",
			"notificationType":2,
			"purchaseToken":"sub-token",
			"subscriptionId":"sub-1"
		},
		"voidedPurchaseNotification":{
			"purchaseToken":"void-token",
			"orderId":"order-1",
			"productType":3,
			"refundType":4
		},
		"testNotification":{
			"version":"1.0"
		}
	}`

	var notification Notification
	if err := json.Unmarshal([]byte(source), &notification); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if notification.Version != "1.0" || notification.PackageName != "com.example.app" {
		t.Fatalf("unexpected notification fields: %#v", notification)
	}

	if notification.OneTimeProductNotification == nil || notification.OneTimeProductNotification.PurchaseToken != "otp-token" {
		t.Fatalf("missing or wrong one-time product notification")
	}

	if notification.SubscriptionNotification == nil || notification.SubscriptionNotification.SubscriptionId != "sub-1" {
		t.Fatalf("missing or wrong subscription notification")
	}

	if notification.VoidedPurchaseNotification == nil || notification.VoidedPurchaseNotification.OrderId != "order-1" {
		t.Fatalf("missing or wrong voided purchase notification")
	}

	if notification.TestNotification == nil || notification.TestNotification.Version != "1.0" {
		t.Fatalf("missing or wrong test notification")
	}
}

func TestStartSubscriptionMonitorWithContextPropagatesReceiveError(t *testing.T) {
	t.Parallel()

	fakeClient := &fakePubSubClient{subscription: &fakePubSubSubscription{errToRet: errors.New("receive failed")}}
	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		return fakeClient, nil
	}

	cfg := &Config{ProjectID: "project-err", SubscriptionID: "sub-err"}
	err := startSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {}, create)
	if err == nil || err.Error() != "receive failed" {
		t.Fatalf("expected receive error to propagate, got %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextFactoryError(t *testing.T) {
	t.Parallel()

	expected := errors.New("create failed")
	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		return nil, expected
	}

	cfg := &Config{ProjectID: "project-factory", SubscriptionID: "sub-factory"}
	err := startSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {}, create)
	if err == nil || err.Error() != "create failed" {
		t.Fatalf("expected factory error to be returned, got %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextNilFactoryError(t *testing.T) {
	t.Parallel()

	err := startSubscriptionMonitorWithContext(context.Background(), &Config{ProjectID: "p", SubscriptionID: "s"}, func(ctx context.Context, msg *pubsub.Message) {}, nil)
	if err == nil {
		t.Fatalf("expected nil client factory error")
	}
	if err.Error() != "client creator is required" {
		t.Fatalf("unexpected factory error: %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextNilClientReturnedError(t *testing.T) {
	t.Parallel()

	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		return nil, nil
	}

	err := startSubscriptionMonitorWithContext(context.Background(), &Config{ProjectID: "p", SubscriptionID: "s"}, func(ctx context.Context, msg *pubsub.Message) {}, create)
	if err == nil {
		t.Fatalf("expected nil client returned error")
	}
	if err.Error() != "pubsub client is nil" {
		t.Fatalf("unexpected nil client error: %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextNilSubscriptionReturnedError(t *testing.T) {
	t.Parallel()

	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		return &nilSubscriptionClient{}, nil
	}

	err := startSubscriptionMonitorWithContext(context.Background(), &Config{ProjectID: "p", SubscriptionID: "s"}, func(ctx context.Context, msg *pubsub.Message) {}, create)
	if err == nil {
		t.Fatalf("expected nil subscription returned error")
	}
	if err.Error() != "pubsub subscription is nil" {
		t.Fatalf("unexpected nil subscription error: %v", err)
	}
}

func TestStartSubscriptionMonitorWithContextRunsReceiveAndClosesClient(t *testing.T) {
	t.Parallel()

	fakeSub := &fakePubSubSubscription{}
	fakeClient := &fakePubSubClient{subscription: fakeSub}
	var gotCtx context.Context

	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		gotCtx = ctx
		fakeClient.projectID = projectID
		fakeClient.options = opts
		return fakeClient, nil
	}

	cfg := &Config{
		ProjectID:      "project-1",
		SubscriptionID: "sub-1",
	}

	called := false
	err := startSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {
		called = true
	}, create)
	if err != nil {
		t.Fatalf("expected successful run with fake client, got %v", err)
	}

	if !called {
		t.Fatalf("expected message handler to be executed")
	}
	if fakeSub.callCount != 1 {
		t.Fatalf("expected receive to be invoked once, got %d", fakeSub.callCount)
	}
	if !fakeClient.closed {
		t.Fatalf("expected client close to be called")
	}
	if fakeClient.projectID != cfg.ProjectID {
		t.Fatalf("unexpected project id: %s", fakeClient.projectID)
	}
	if fakeClient.subscriptionID != cfg.SubscriptionID {
		t.Fatalf("unexpected subscription id: %s", fakeClient.subscriptionID)
	}
	if gotCtx == nil {
		t.Fatalf("expected context passed to client creator")
	}
}

func TestStartSubscriptionMonitorWithContextClosesClientOnReceiveError(t *testing.T) {
	t.Parallel()

	fakeSub := &fakePubSubSubscription{errToRet: errors.New("receive failed")}
	fakeClient := &fakePubSubClient{subscription: fakeSub}

	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		return fakeClient, nil
	}

	err := startSubscriptionMonitorWithContext(context.Background(), &Config{ProjectID: "project", SubscriptionID: "sub"}, func(ctx context.Context, msg *pubsub.Message) {}, create)
	if err == nil || err.Error() != "receive failed" {
		t.Fatalf("expected receive error, got: %v", err)
	}
	if !fakeClient.closed {
		t.Fatalf("expected client to close on receive error")
	}
	if fakeSub.callCount != 1 {
		t.Fatalf("expected receive to be called once, got %d", fakeSub.callCount)
	}
}

func TestStartSubscriptionMonitorWithContextHonorsNilContext(t *testing.T) {
	t.Parallel()

	fakeClient := &fakePubSubClient{subscription: &fakePubSubSubscription{}}
	var gotCtx context.Context

	create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
		gotCtx = ctx
		return fakeClient, nil
	}

	cfg := &Config{ProjectID: "project-2", SubscriptionID: "sub-2"}

	if err := startSubscriptionMonitorWithContext(nil, cfg, func(ctx context.Context, msg *pubsub.Message) {}, create); err != nil {
		t.Fatalf("expected success with nil context using background, got %v", err)
	}

	if gotCtx != context.Background() {
		t.Fatalf("expected background context fallback when ctx is nil")
	}
}

func TestStartSubscriptionMonitorWithContextCredentialOptionTypes(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "creds.json")
	if err := os.WriteFile(credFile, []byte("{\"type\":\"service_account\"}"), 0o600); err != nil {
		t.Fatalf("create credential file failed: %v", err)
	}

	testCases := []struct {
		name    string
		jsonKey string
		hasFile bool
	}{
		{name: "file credentials", jsonKey: credFile, hasFile: true},
		{name: "inline credentials", jsonKey: "{\"type\":\"service_account\"}"},
		{name: "missing file credentials", jsonKey: filepath.Join(tmpDir, "missing.json")},
		{name: "no credentials", jsonKey: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := &fakePubSubClient{subscription: &fakePubSubSubscription{}}
			create := func(ctx context.Context, projectID string, opts ...option.ClientOption) (pubSubClient, error) {
				fakeClient.options = opts
				return fakeClient, nil
			}

			cfg := &Config{ProjectID: "project-3", SubscriptionID: "sub-3", JsonKey: tc.jsonKey}
			if err := startSubscriptionMonitorWithContext(context.Background(), cfg, func(ctx context.Context, msg *pubsub.Message) {}, create); err != nil {
				t.Fatalf("expected run success with fake client, got %v", err)
			}

			if len(fakeClient.options) > 0 {
				optType := fmt.Sprintf("%T", fakeClient.options[0])
				if tc.hasFile {
					if !strings.Contains(optType, "withCredFile") {
						t.Fatalf("expected credentials file option, got %s", optType)
					}
				} else if tc.jsonKey != "" {
					if !strings.Contains(optType, "withCredentialsJSON") {
						t.Fatalf("expected credentials JSON option, got %s", optType)
					}
				}
			}

			if tc.hasFile {
				if len(fakeClient.options) != 1 {
					t.Fatalf("expected one option for file credentials")
				}
			} else if tc.jsonKey != "" {
				if len(fakeClient.options) != 1 {
					t.Fatalf("expected one option for inline credentials")
				}
			} else if len(fakeClient.options) != 0 {
				t.Fatalf("expected no options when json key is empty")
			}
		})
	}
}
