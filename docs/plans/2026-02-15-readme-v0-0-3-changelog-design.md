# README v0.0.3 Changelog Design

## Goal
- Add a v0.0.3 changelog entry to the README using the existing v0.0.2 format.

## Non-Goals
- Updating CHANGELOG.md or other documentation files.
- Changing README structure outside the changelog section.

## Placement
- Insert the v0.0.3 entry at the top of the README changelog section, above v0.0.2.

## Structure
- Use the same sections as v0.0.2:
  - Version header with timestamp and commit SHA
  - 变更要点
  - 版本元信息

## Content
- 变更要点
  - Unified purchase/subscription query APIs and tests
  - Mixed-input validation for publisher queries
  - Remove docs directory from repository
- 版本元信息
  - 发布提交: latest commit on the branch that includes docs removal
  - 提交范围: previous release commit to new release commit
  - 验证: `go test ./...`
  - PR: link to PR #2
  - 发布说明: link to v0.0.3 release
