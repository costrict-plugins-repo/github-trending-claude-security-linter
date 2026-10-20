# Security Linter Plugin

A PreToolUse hook plugin for Claude Code that scans code for security vulnerabilities before it is written to disk.

## What It Detects

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| EVAL_USAGE | `eval()` calls | Error (blocks) |
| FUNCTION_CONSTRUCTOR | `new Function()` / `Function()` | Error (blocks) |
| HARDCODED_API_KEY | `api_key = "..."` and variants | Error (blocks) |
| HARDCODED_SECRET | `password = "..."`, `secret_key = "..."` | Error (blocks) |
| BEARER_TOKEN | `"Bearer eyJ..."` hardcoded tokens | Error (blocks) |
| AWS_ACCESS_KEY | `AKIA...` access key IDs | Error (blocks) |
| AWS_SECRET_KEY | `aws_secret_access_key = "..."` | Error (blocks) |
| INNERHTML_ASSIGNMENT | `.innerHTML =` / `.outerHTML =` | Error (blocks) |
| PRIVATE_KEY_INLINE | PEM-encoded private keys | Error (blocks) |
| GITHUB_TOKEN | `ghp_...` / `github_pat_...` tokens | Error (blocks) |
| DOCUMENT_WRITE | `document.write()` | Warning (non-blocking) |
| DANGEROUSLY_SET_INNERHTML | React `dangerouslySetInnerHTML` | Warning (non-blocking) |

## How It Works

1. The hook intercepts every `Write`, `Edit`, and `MultiEdit` tool call.
2. It extracts the code content from the tool input (handling each tool's JSON shape).
3. Content is scanned against all regex patterns, skipping matches inside comments.
4. **Errors** block the write with a detailed denial message listing every violation.
5. **Warnings** allow the write but inject advisory context for Claude to consider.
6. The linter always exits 0 (fail-open) — if the linter itself errors, writes are not blocked.

## Installation

```bash
claude --plugin-dir /path/to/security-linter
```

Verify it loaded:

```bash
/plugins list
```

## Requirements

- Node.js >= 14 (no npm dependencies)

Run the check script:

```bash
bash /path/to/security-linter/scripts/install-deps.sh
```
