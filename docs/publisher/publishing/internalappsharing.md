# internalappsharing — 内部应用共享产物上传

封装 `androidpublisher.Internalappsharingartifacts` 资源，用于将 APK 或 AAB 上传到 Play Console 的内部应用分享通道（生成可分享的安装链接）。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/internalappsharing`
- Scope: `https://www.googleapis.com/auth/androidpublisher`
- 两个方法都接受 `io.Reader` 作为上传源。

## 快速示例

```go
f, _ := os.Open("app-release.aab")
defer f.Close()

artifact, err := client.InternalAppSharing.UploadBundle(ctx, "com.example.app", f)
if err != nil {
    log.Fatal(err)
}
fmt.Println("download URL:", artifact.DownloadUrl)
```

## UploadAPK

```go
func (s *Service) UploadAPK(ctx context.Context, packageName string, media io.Reader) (*androidpublisher.InternalAppSharingArtifact, error)
```

REST: `POST /androidpublisher/v3/applications/internalappsharing/{packageName}/artifacts/apk`

## UploadBundle

```go
func (s *Service) UploadBundle(ctx context.Context, packageName string, media io.Reader) (*androidpublisher.InternalAppSharingArtifact, error)
```

REST: `POST /androidpublisher/v3/applications/internalappsharing/{packageName}/artifacts/bundle`
