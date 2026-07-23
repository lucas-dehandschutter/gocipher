---
description: Updates the Go version, all dependencies, and runs a vulnerability check
argument-hint: [optional module to target]
allowed-tools: Bash(go:*), Bash(govulncheck:*), Bash(git diff:*), Bash(git status:*), Read, Edit
---

# Context

- Current Go version in go.mod: !`go list -m -f '{{.GoVersion}}'`
- Locally installed Go version: !`go version`
- Repo status: !`git status --short`

# Task

1. Determine the latest stable Go release available and update the `go`
   directive in `go.mod` accordingly (use `go mod edit -go=X.Y`). Never
   downgrade the version, only bump it up.
2. Update all dependencies to their latest compatible minor/patch versions
   with `go get -u ./...`, then clean up with `go mod tidy`.
3. Make sure the module still builds: `go build ./...`.
4. Run the tests: `go test ./...` and report any failures.
5. If `govulncheck` is not installed, offer to install it
   (`go install golang.org/x/vuln/cmd/govulncheck@latest`), then run
   `govulncheck ./...` and summarize the vulnerabilities found, noting
   which ones are fixed by the updates just performed and which ones
   still need manual action.
6. Finish with a clear summary: Go version before/after, changed
   dependencies (via `git diff go.mod go.sum`), test results, and
   vulnerability scan results.

Do not commit anything automatically — let me review the diff first.
