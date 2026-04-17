# edits — Play Console 编辑事务（完整生命周期 + 所有嵌套资源）

封装 `androidpublisher.Edits` 资源树。对 Play Console 的几乎所有元数据修改都必须走 `edits` 事务：`Insert` 开一个 edit → 在其中修改 APK / 列表 / 轨道等嵌套资源 → `Validate`（可选）→ `Commit`（或 `Delete` 丢弃）。

- Go 包路径: `github.com/godrealms/go-google-sdk/android/publisher/edits`
- Scope: `https://www.googleapis.com/auth/androidpublisher`

## 生命周期概览

```go
// 1. 开启 edit
edit, err := client.Edits.Insert(ctx, "com.example.app", nil)
editID := edit.Id

// 2. 在 edit 内修改资源（示例：上传 AAB 并加入 internal 轨道）
f, _ := os.Open("app.aab")
defer f.Close()
bundle, _ := client.Edits.BundlesUpload(ctx, "com.example.app", editID, f, edits.BundlesUploadOptions{})

_, _ = client.Edits.TracksUpdate(ctx, "com.example.app", editID, "internal", &androidpublisher.Track{
    Releases: []*androidpublisher.TrackRelease{{
        Status:       "completed",
        VersionCodes: []int64{bundle.VersionCode},
    }},
})

// 3. 校验 + 提交
if _, err := client.Edits.Validate(ctx, "com.example.app", editID); err != nil {
    _ = client.Edits.Delete(ctx, "com.example.app", editID)
    log.Fatal(err)
}
_, err = client.Edits.Commit(ctx, "com.example.app", editID, edits.CommitOptions{})
```

## 顶层 Edit 生命周期

### Insert

```go
func (s *Service) Insert(ctx context.Context, packageName string, edit *androidpublisher.AppEdit) (*androidpublisher.AppEdit, error)
```

`edit` 可以传 `nil`，SDK 会自动发空请求体。

REST: `POST /androidpublisher/v3/applications/{packageName}/edits`

### Get

```go
func (s *Service) Get(ctx context.Context, packageName, editID string) (*androidpublisher.AppEdit, error)
```

REST: `GET /androidpublisher/v3/applications/{packageName}/edits/{editId}`

### Validate

服务端校验但不提交。

```go
func (s *Service) Validate(ctx context.Context, packageName, editID string) (*androidpublisher.AppEdit, error)
```

REST: `POST /androidpublisher/v3/applications/{packageName}/edits/{editId}:validate`

### Commit

```go
func (s *Service) Commit(ctx context.Context, packageName, editID string, opts CommitOptions) (*androidpublisher.AppEdit, error)
```

`CommitOptions{ChangesNotSentForReview bool}` — 设为 `true` 时变更不进人工审核队列（仅适用于测试轨道或无审核需求的字段）。

REST: `POST /androidpublisher/v3/applications/{packageName}/edits/{editId}:commit`

### Delete

丢弃 edit。

```go
func (s *Service) Delete(ctx context.Context, packageName, editID string) error
```

REST: `DELETE /androidpublisher/v3/applications/{packageName}/edits/{editId}`

---

## Apks

### ApksList

```go
func (s *Service) ApksList(ctx, packageName, editID) (*androidpublisher.ApksListResponse, error)
```

`GET .../edits/{editId}/apks`

### ApksUpload

`media io.Reader` 上传 APK。

```go
func (s *Service) ApksUpload(ctx, packageName, editID string, media io.Reader) (*androidpublisher.Apk, error)
```

```go
f, _ := os.Open("app.apk")
defer f.Close()
apk, err := client.Edits.ApksUpload(ctx, "com.example.app", editID, f)
```

`POST /upload/androidpublisher/v3/applications/{packageName}/edits/{editId}/apks`

### ApksAddExternallyHosted

企业发布专用，注册外部托管 APK。

```go
func (s *Service) ApksAddExternallyHosted(ctx, packageName, editID, req) (*androidpublisher.ApksAddExternallyHostedResponse, error)
```

`POST .../edits/{editId}/apks/externallyHosted`

---

## Bundles

### BundlesList

```go
func (s *Service) BundlesList(ctx, packageName, editID) (*androidpublisher.BundlesListResponse, error)
```

`GET .../edits/{editId}/bundles`

### BundlesUpload

```go
func (s *Service) BundlesUpload(ctx, packageName, editID string, media io.Reader, opts BundlesUploadOptions) (*androidpublisher.Bundle, error)
```

`BundlesUploadOptions{AckBundleInstallationWarning, DeviceTierConfigID}`。

`POST /upload/androidpublisher/v3/applications/{packageName}/edits/{editId}/bundles`

---

## CountryAvailability

### CountryAvailabilityGet

查询某个轨道在各国家 / 地区的可用性。

```go
func (s *Service) CountryAvailabilityGet(ctx, packageName, editID, track string) (*androidpublisher.TrackCountryAvailability, error)
```

`GET .../edits/{editId}/countryAvailability/{track}`

---

## DeobfuscationFiles

### DeobfuscationFilesUpload

上传混淆映射文件 / Native symbols。

```go
func (s *Service) DeobfuscationFilesUpload(ctx, packageName, editID string, apkVersionCode int64, deobfuscationFileType string, media io.Reader) (*androidpublisher.DeobfuscationFilesUploadResponse, error)
```

`deobfuscationFileType` 取值：`proguard` / `nativeCode`。

`POST /upload/.../edits/{editId}/apks/{apkVersionCode}/deobfuscationFiles/{deobfuscationFileType}`

---

## Details

### DetailsGet / DetailsPatch / DetailsUpdate

```go
func (s *Service) DetailsGet(ctx, packageName, editID) (*androidpublisher.AppDetails, error)
func (s *Service) DetailsPatch(ctx, packageName, editID, *androidpublisher.AppDetails) (*androidpublisher.AppDetails, error)
func (s *Service) DetailsUpdate(ctx, packageName, editID, *androidpublisher.AppDetails) (*androidpublisher.AppDetails, error)
```

- Patch: 部分更新 (`PATCH`)
- Update: 全量替换 (`PUT`)

`.../edits/{editId}/details`

---

## ExpansionFiles

版本 OBB 扩展文件管理。`expansionFileType` 取值：`main` / `patch`。

```go
func (s *Service) ExpansionFilesGet(ctx, packageName, editID, apkVersionCode, expansionFileType) (*androidpublisher.ExpansionFile, error)
func (s *Service) ExpansionFilesPatch(ctx, packageName, editID, apkVersionCode, expansionFileType, *androidpublisher.ExpansionFile) (*androidpublisher.ExpansionFile, error)
func (s *Service) ExpansionFilesUpdate(ctx, packageName, editID, apkVersionCode, expansionFileType, *androidpublisher.ExpansionFile) (*androidpublisher.ExpansionFile, error)
func (s *Service) ExpansionFilesUpload(ctx, packageName, editID, apkVersionCode, expansionFileType, media io.Reader) (*androidpublisher.ExpansionFilesUploadResponse, error)
```

`.../edits/{editId}/apks/{apkVersionCode}/expansionFiles/{expansionFileType}`
上传走 `/upload/` 前缀。

---

## Images

语言 × 图片类型（`icon` / `featureGraphic` / `phoneScreenshots` 等）下的截图与资源管理。

```go
func (s *Service) ImagesList(ctx, packageName, editID, language, imageType) (*androidpublisher.ImagesListResponse, error)
func (s *Service) ImagesUpload(ctx, packageName, editID, language, imageType string, media io.Reader) (*androidpublisher.ImagesUploadResponse, error)
func (s *Service) ImagesDelete(ctx, packageName, editID, language, imageType, imageID) error
func (s *Service) ImagesDeleteAll(ctx, packageName, editID, language, imageType) (*androidpublisher.ImagesDeleteAllResponse, error)
```

```go
f, _ := os.Open("icon.png")
defer f.Close()
_, err := client.Edits.ImagesUpload(ctx, "com.example.app", editID, "en-US", "icon", f)
```

`.../edits/{editId}/listings/{language}/{imageType}/...`

---

## Listings

各语言 Store Listing（描述、短介绍、视频）。

```go
func (s *Service) ListingsList(ctx, packageName, editID) (*androidpublisher.ListingsListResponse, error)
func (s *Service) ListingsGet(ctx, packageName, editID, language) (*androidpublisher.Listing, error)
func (s *Service) ListingsPatch(ctx, packageName, editID, language, *androidpublisher.Listing) (*androidpublisher.Listing, error)
func (s *Service) ListingsUpdate(ctx, packageName, editID, language, *androidpublisher.Listing) (*androidpublisher.Listing, error)
func (s *Service) ListingsDelete(ctx, packageName, editID, language) error
func (s *Service) ListingsDeleteAll(ctx, packageName, editID) error
```

`.../edits/{editId}/listings[/{language}]`

---

## Testers

管理 closed / internal 轨道的测试名单。

```go
func (s *Service) TestersGet(ctx, packageName, editID, track) (*androidpublisher.Testers, error)
func (s *Service) TestersPatch(ctx, packageName, editID, track, *androidpublisher.Testers) (*androidpublisher.Testers, error)
func (s *Service) TestersUpdate(ctx, packageName, editID, track, *androidpublisher.Testers) (*androidpublisher.Testers, error)
```

`.../edits/{editId}/testers/{track}`

---

## Tracks

分发轨道（`internal`/`alpha`/`beta`/`production` 或自定义）。

```go
func (s *Service) TracksCreate(ctx, packageName, editID string, cfg *androidpublisher.TrackConfig) (*androidpublisher.Track, error)
func (s *Service) TracksGet(ctx, packageName, editID, track) (*androidpublisher.Track, error)
func (s *Service) TracksList(ctx, packageName, editID) (*androidpublisher.TracksListResponse, error)
func (s *Service) TracksPatch(ctx, packageName, editID, track, *androidpublisher.Track) (*androidpublisher.Track, error)
func (s *Service) TracksUpdate(ctx, packageName, editID, track, *androidpublisher.Track) (*androidpublisher.Track, error)
```

```go
_, err := client.Edits.TracksUpdate(ctx, "com.example.app", editID, "production", &androidpublisher.Track{
    Releases: []*androidpublisher.TrackRelease{{
        Name:         "2026.04 hotfix",
        Status:       "completed",
        VersionCodes: []int64{10022},
    }},
})
```

`.../edits/{editId}/tracks[/{track}]`
