# applications — 数据安全、设备分级配置、跨轨道发布列表

封装 `androidpublisher.Applications` 下几个零散子资源。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/applications`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## DataSafety

更新应用的数据安全表单。

```go
func (s *Service) DataSafety(ctx context.Context, packageName string, req *androidpublisher.SafetyLabelsUpdateRequest) (*androidpublisher.SafetyLabelsUpdateResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/dataSafety`

```go
_, err := client.Applications.DataSafety(ctx, "com.example.app",
    &androidpublisher.SafetyLabelsUpdateRequest{SafetyLabels: "..."})
```

## CreateDeviceTierConfig

```go
func (s *Service) CreateDeviceTierConfig(ctx context.Context, packageName string, cfg *androidpublisher.DeviceTierConfig, opts CreateDeviceTierConfigOptions) (*androidpublisher.DeviceTierConfig, error)
```

`CreateDeviceTierConfigOptions{AllowUnknownDevices}`。

REST: `POST /androidpublisher/v3/applications/{packageName}/deviceTierConfigs`

## GetDeviceTierConfig

```go
func (s *Service) GetDeviceTierConfig(ctx context.Context, packageName string, deviceTierConfigID int64) (*androidpublisher.DeviceTierConfig, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/deviceTierConfigs/{deviceTierConfigId}`

## ListDeviceTierConfigs

```go
func (s *Service) ListDeviceTierConfigs(ctx context.Context, packageName string, opts ListDeviceTierConfigsOptions) (*androidpublisher.ListDeviceTierConfigsResponse, error)
```

`ListDeviceTierConfigsOptions{PageSize, PageToken}`。

REST: `GET /androidpublisher/v3/applications/{packageName}/deviceTierConfigs`

## ListTrackReleases

列出某个轨道 (track) 下所有发布摘要。`parent` 格式为 `applications/{packageName}/tracks/{trackId}`。

```go
func (s *Service) ListTrackReleases(ctx context.Context, parent string) (*androidpublisher.ListReleaseSummariesResponse, error)
```

REST: `GET /androidpublisher/v3/{parent=applications/*/tracks/*}/releases`

```go
resp, err := client.Applications.ListTrackReleases(ctx,
    "applications/com.example.app/tracks/production")
```
