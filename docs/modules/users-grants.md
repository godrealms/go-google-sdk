# users + grants — Play Console 用户与权限管理

封装 `androidpublisher.Users` 与 `androidpublisher.Grants` 两个资源：前者是开发者账号下的用户（邀请、撤销、修改角色），后者是用户对特定 App 的访问权限。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/users`, `.../grants`
- Scope: `https://www.googleapis.com/auth/androidpublisher`
- 资源名格式：
  - `parent (users)`: `developers/{developerId}`
  - `name  (users)`: `developers/{developerId}/users/{email}`
  - `parent (grants)`: `developers/{developerId}/users/{email}`
  - `name  (grants)`: `developers/{developerId}/users/{email}/grants/{packageName}`

## 快速示例

```go
parent := "developers/1234567890"

// 列出所有用户
list, err := client.Users.List(ctx, parent, users.ListOptions{PageSize: 50})

// 给某个用户添加应用级授权
_, err = client.Grants.Create(ctx, parent+"/users/alice@example.com",
    &androidpublisher.Grant{
        PackageName:         "com.example.app",
        AppLevelPermissions: []string{"CAN_VIEW_FINANCIAL_DATA_GLOBAL"},
    })
```

## Users.Create

```go
func (s *Service) Create(ctx context.Context, parent string, user *androidpublisher.User) (*androidpublisher.User, error)
```

REST: `POST /androidpublisher/v3/{parent=developers/*}/users`

## Users.List

```go
func (s *Service) List(ctx context.Context, parent string, opts ListOptions) (*androidpublisher.ListUsersResponse, error)
```

`ListOptions{PageSize, PageToken}`。

REST: `GET /androidpublisher/v3/{parent=developers/*}/users`

## Users.Patch

```go
func (s *Service) Patch(ctx context.Context, name, updateMask string, user *androidpublisher.User) (*androidpublisher.User, error)
```

REST: `PATCH /androidpublisher/v3/{name=developers/*/users/*}`

```go
_, err := client.Users.Patch(ctx,
    "developers/1234567890/users/alice@example.com",
    "developerAccountPermissions",
    &androidpublisher.User{
        DeveloperAccountPermissions: []string{"CAN_MANAGE_PERMISSIONS"},
    })
```

## Users.Delete

```go
func (s *Service) Delete(ctx context.Context, name string) error
```

REST: `DELETE /androidpublisher/v3/{name=developers/*/users/*}`

## Grants.Create

```go
func (s *Service) Create(ctx context.Context, parent string, grant *androidpublisher.Grant) (*androidpublisher.Grant, error)
```

REST: `POST /androidpublisher/v3/{parent=developers/*/users/*}/grants`

## Grants.Patch

```go
func (s *Service) Patch(ctx context.Context, name, updateMask string, grant *androidpublisher.Grant) (*androidpublisher.Grant, error)
```

REST: `PATCH /androidpublisher/v3/{name=developers/*/users/*/grants/*}`

## Grants.Delete

```go
func (s *Service) Delete(ctx context.Context, name string) error
```

REST: `DELETE /androidpublisher/v3/{name=developers/*/users/*/grants/*}`
