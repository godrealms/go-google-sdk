# Feature Delivery Workflow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Establish a repeatable Go workflow for implementing small-to-medium features with TDD, focused changes, and PR-grade verification.

**Architecture:** Keep production changes in small, package-scoped commits, with tests in the same package (`*_test.go`) and shared helpers under `payment/payment_test_utils_test.go` when needed. Validation is done locally first, then via PR checks.

**Tech Stack:** Go modules (`go.mod`), Go testing (`go test`), GitHub CLI (`gh`), Bash scripts, and Git branches/PR workflow.

---

### Task 1: Prepare feature branch and baseline

**Files:**
- `docs/plans/2026-02-15-golang-workflow.md` (created)

**Step 1: Create and switch to a feature branch**

Run: `git checkout main && git pull --ff-only && git checkout -b feature/<short-name>`

Expected: branch is clean and points at latest `origin/main`.

**Step 2: Verify branch context is clean**

Run: `git status -sb`

Expected: no local modified/untracked files.

### Task 2: Add a focused failing test

**Files:**
- `payment/<feature>_test.go` (new)

**Step 1: Write the failing test**

```go
func TestNewBehaviorRejectsInvalidInput(t *testing.T) {
	t := &TokenHandler{}
	err := t.someNewBehavior("")
	if err == nil {
		t.Fatalf("expected failure for invalid input")
	}
}
```

**Step 2: Run the test to confirm failure**

Run: `go test ./payment -run TestNewBehaviorRejectsInvalidInput -v`

Expected: test fails, showing missing/incorrect behavior.

### Task 3: Implement minimal production change

**Files:**
- `payment/<feature>.go` (existing)

**Step 1: Add minimal logic to satisfy the failing test**

```go
func (t *TokenHandler) someNewBehavior(input string) error {
	if input == "" {
		return errors.New("invalid input")
	}
	return nil
}
```

**Step 2: Re-run the test**

Run: `go test ./payment -run TestNewBehaviorRejectsInvalidInput -v`

Expected: test passes.

### Task 4: Expand coverage and run full package verification

**Files:**
- `payment/<feature>_test.go` (modify)

**Step 1: Add edge-path tests (error and branch cases)**

- Add at least one test for empty/invalid input
- Add one test for a valid path
- Add one test for fallback/refresh failure path if relevant

**Step 2: Run full package tests**

Run: `go test ./payment -v`

Expected: all tests in package pass.

### Task 5: Run project-wide verification and capture evidence

**Files:**
- `docs/plans/2026-02-15-golang-workflow.md` (add verification notes)

**Step 1: Run full test suite**

Run: `go test ./...`

Expected: all package tests pass.

**Step 2: Record coverage and save artifact (optional for coverage-focused tasks)**

Run: `go test -coverprofile=payment/coverage.out ./payment`

Expected: coverage output file created at `payment/coverage.out`.

### Task 6: Commit and open PR scope-correctly

**Files:**
- all touched production and test files for the feature

**Step 1: Commit in one atomic chunk**

Run:

```bash
git add payment/*.go payment/*_test.go docs/plans/2026-02-15-golang-workflow.md
git commit -m "feat(payment): implement <short description> with tests"
```

Expected: one clean commit containing scoped code and tests.

**Step 2: Push branch and create PR**

Run:

```bash
git push -u origin feature/<short-name>
gh pr create --title "feat(payment): <short description>" --body "## Summary\n- ...\n\n## Test Plan\n- [x] go test ./..."
```

Expected: PR is opened and ready for review.

### Task 7: Post-merge sync and handoff

**Files:**
- local git branches only

**Step 1: Sync main after merge**

Run: `git checkout main && git pull --ff-only`

Expected: `main` includes merged commit and is clean.

**Step 2: Resolve local branch state**

Run: `git branch -D feature/<short-name>`

Expected: temporary feature branch removed after handoff.
