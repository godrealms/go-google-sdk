# reviews — 用户评论查询与开发者回复

封装 `androidpublisher.Reviews` 资源。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/reviews`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## 快速示例

```go
list, err := client.Reviews.List(ctx, "com.example.app", reviews.ListOptions{
    MaxResults: 50,
})
for _, r := range list.Reviews {
    fmt.Println(r.ReviewId, r.AuthorName)
}
```

## Get

```go
func (s *Service) Get(ctx context.Context, packageName, reviewID, translationLanguage string) (*androidpublisher.Review, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/reviews/{reviewId}`

```go
review, err := client.Reviews.Get(ctx, "com.example.app", reviewID, "en")
```

## List

```go
func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ReviewsListResponse, error)
```

`ListOptions` 支持 `MaxResults`、`StartIndex`、`Token`（分页游标）、`TranslationLanguage`。

REST: `GET /androidpublisher/v3/applications/{packageName}/reviews`

## Reply

发布开发者回复。

```go
func (s *Service) Reply(ctx context.Context, packageName, reviewID, replyText string) (*androidpublisher.ReviewsReplyResponse, error)
```

```go
resp, err := client.Reviews.Reply(ctx, "com.example.app", reviewID,
    "感谢反馈，问题已在下个版本修复。")
```

REST: `POST /androidpublisher/v3/applications/{packageName}/reviews/{reviewId}:reply`
