# generatedapks + systemapks — 构建分发（生成 APK / 系统 APK 变体）

封装两个构建产物相关的资源：

- `generatedapks`：Google Play 由 AAB 生成的拆分 APK。
- `systemapks`：系统镜像 / 预装用的 APK 变体。

Go 包路径：
- `github.com/godrealms/go-google-sdk/android/publisher/generatedapks`
- `github.com/godrealms/go-google-sdk/android/publisher/systemapks`

Scope: `https://www.googleapis.com/auth/androidpublisher`

## GeneratedAPKs.List

列出版本对应的所有生成 APK 变体。

```go
func (s *Service) List(ctx context.Context, packageName string, versionCode int64) (*androidpublisher.GeneratedApksListResponse, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/generatedApks/{versionCode}`

```go
list, err := client.GeneratedAPKs.List(ctx, "com.example.app", 10021)
```

## GeneratedAPKs.Download

返回 `io.ReadCloser`，调用方必须关闭。

```go
func (s *Service) Download(ctx context.Context, packageName string, versionCode int64, downloadID string) (io.ReadCloser, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/generatedApks/{versionCode}/downloads/{downloadId}:download`

```go
body, err := client.GeneratedAPKs.Download(ctx, "com.example.app", 10021, "xxhdpi-arm64")
if err != nil {
    log.Fatal(err)
}
defer body.Close()
_, _ = io.Copy(f, body)
```

## SystemAPKs.Create

申请新系统变体。

```go
func (s *Service) Create(ctx context.Context, packageName string, versionCode int64, variant *androidpublisher.Variant) (*androidpublisher.Variant, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants`

## SystemAPKs.Get / List

```go
func (s *Service) Get(ctx context.Context, packageName string, versionCode, variantID int64) (*androidpublisher.Variant, error)
func (s *Service) List(ctx context.Context, packageName string, versionCode int64) (*androidpublisher.SystemApksListResponse, error)
```

REST:
- `GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants/{variantId}`
- `GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants`

## SystemAPKs.Download

返回 `io.ReadCloser`，调用方关闭。

```go
func (s *Service) Download(ctx context.Context, packageName string, versionCode, variantID int64) (io.ReadCloser, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/systemApks/{versionCode}/variants/{variantId}:download`

```go
body, err := client.SystemAPKs.Download(ctx, "com.example.app", 10021, 1)
defer body.Close()
```
