# apprecovery — 应用恢复（回滚 / 重新分发）

封装 `androidpublisher.Apprecovery` 资源，用于发起紧急回滚或定向修复发布。动作通过 `(packageName, appRecoveryId int64)` 唯一定位。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/apprecovery`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## 快速示例

```go
action, err := client.AppRecovery.Create(ctx, "com.example.app",
    &androidpublisher.CreateDraftAppRecoveryRequest{/* TargetingUpdate 等 */})

_, _ = client.AppRecovery.Deploy(ctx, "com.example.app", action.AppRecoveryId, nil)
```

## Create

```go
func (s *Service) Create(ctx context.Context, packageName string, req *androidpublisher.CreateDraftAppRecoveryRequest) (*androidpublisher.AppRecoveryAction, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/appRecoveries`

## AddTargeting

扩展恢复动作的设备覆盖范围。

```go
func (s *Service) AddTargeting(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.AddTargetingRequest) (*androidpublisher.AddTargetingResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:addTargeting`

## Cancel

中止正在进行的恢复。

```go
func (s *Service) Cancel(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.CancelAppRecoveryRequest) (*androidpublisher.CancelAppRecoveryResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:cancel`

## Deploy

将 Draft 态的恢复动作推到正式分发。

```go
func (s *Service) Deploy(ctx context.Context, packageName string, appRecoveryID int64, req *androidpublisher.DeployAppRecoveryRequest) (*androidpublisher.DeployAppRecoveryResponse, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/appRecoveries/{appRecoveryId}:deploy`

## List

```go
func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ListAppRecoveriesResponse, error)
```

`ListOptions{VersionCode}`。

REST: `GET /androidpublisher/v3/applications/{packageName}/appRecoveries`

```go
list, err := client.AppRecovery.List(ctx, "com.example.app",
    apprecovery.ListOptions{VersionCode: 10021})
```
