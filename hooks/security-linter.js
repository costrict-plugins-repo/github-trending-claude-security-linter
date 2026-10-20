#!/usr/bin/env node

/**
 * Security Linter Hook for Claude Code
 *
 * PreToolUse hook that intercepts Write, Edit, and MultiEdit tool calls
 * and scans the content for dangerous patterns before allowing the write.
 *
 * Input:  JSON on stdin with tool_name and tool_input fields
 * Output: JSON on stdout with hookSpecificOutput for PreToolUse decisions
 *
 * Exit 0 always (fail-open). Blocking is done via permissionDecision: "deny".
 */

"use strict";

// ─── Security Pattern Definitions ──────────────────────────────────────────

const SECURITY_PATTERNS = [
  // eval() and dynamic code execution
  {
    id: "EVAL_USAGE",
    name: "eval() usage",
    pattern: /\beval\s*\(/g,
    severity: "error",
    message:
      "Direct eval() usage detected. eval() executes arbitrary code and is a " +
      "major security risk. Use JSON.parse() for data, new Map() for dynamic " +
      "lookups, or a proper expression parser for user expressions.",
  },

  // Function constructor abuse
  {
    id: "FUNCTION_CONSTRUCTOR",
    name: "Function constructor",
    pattern: /\bnew\s+Function\s*[\(`]|[^.\w]Function\s*\(/g,
    severity: "error",
    message:
      "Function constructor detected. new Function() and Function() are " +
      "equivalent to eval() and execute arbitrary strings as code. Use " +
      "regular function declarations or arrow functions instead.",
  },

  // Hardcoded API keys
  {
    id: "HARDCODED_API_KEY",
    name: "Hardcoded API key",
    pattern:
      /(?:api[_-]?key|apikey|api[_-]?secret|apisecret)\s*[:=]\s*["'][a-zA-Z0-9_\-/.]{8,}["']/gi,
    severity: "error",
    message:
      "Hardcoded API key detected. Never embed API keys in source code. " +
      "Use environment variables (process.env.API_KEY) or a secrets manager.",
  },

  // Hardcoded secrets and passwords
  {
    id: "HARDCODED_SECRET",
    name: "Hardcoded secret/password",
    pattern:
      /(?:secret|secret[_-]?key|password|passwd|db[_-]?password|private[_-]?key|encryption[_-]?key|signing[_-]?key)\s*[:=]\s*["'][^\s"']{8,}["']/gi,
    severity: "error",
    message:
      "Hardcoded secret or password detected. Store secrets in environment " +
      "variables or a secrets manager, never in source code.",
  },

  // Bearer tokens
  {
    id: "BEARER_TOKEN",
    name: "Hardcoded Bearer token",
    pattern: /["']Bearer\s+[a-zA-Z0-9_\-/.+=]{20,}["']/g,
    severity: "error",
    message:
      "Hardcoded Bearer token detected. Authentication tokens must not be " +
      "embedded in source code. Use environment variables or a token refresh " +
      "mechanism.",
  },

  // AWS Access Key ID
  {
    id: "AWS_ACCESS_KEY",
    name: "AWS Access Key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "error",
    message:
      "AWS Access Key ID detected (starts with AKIA). Never hardcode AWS " +
      "credentials. Use IAM roles, environment variables, or AWS credential " +
      "files (~/.aws/credentials).",
  },

  // AWS Secret Access Key
  {
    id: "AWS_SECRET_KEY",
    name: "AWS Secret Access Key",
    pattern:
      /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["'][a-zA-Z0-9/+=]{40}["']/gi,
    severity: "error",
    message:
      "AWS Secret Access Key detected. Use IAM roles, environment variables, " +
      "or the AWS credentials file instead of hardcoding secrets.",
  },

  // innerHTML / outerHTML assignment (XSS vector)
  {
    id: "INNERHTML_ASSIGNMENT",
    name: "innerHTML assignment",
    pattern: /\.innerHTML\s*\+?=|\.outerHTML\s*\+?=/g,
    severity: "error",
    message:
      "Direct innerHTML/outerHTML assignment detected. This creates XSS " +
      "vulnerabilities if the content includes user input. Use textContent " +
      "for text, or a sanitizer like DOMPurify for HTML content.",
  },

  // document.write
  {
    id: "DOCUMENT_WRITE",
    name: "document.write()",
    pattern: /\bdocument\.write\s*\(/g,
    severity: "warning",
    message:
      "document.write() detected. This can be used for XSS attacks and " +
      "interferes with page rendering. Use DOM manipulation methods instead.",
  },

  // dangerouslySetInnerHTML (React)
  {
    id: "DANGEROUSLY_SET_INNERHTML",
    name: "dangerouslySetInnerHTML",
    pattern: /dangerouslySetInnerHTML/g,
    severity: "warning",
    message:
      "dangerouslySetInnerHTML detected. Ensure the HTML content is properly " +
      "sanitized with DOMPurify or a similar library before rendering.",
  },

  // Inline private keys
  {
    id: "PRIVATE_KEY_INLINE",
    name: "Inline private key",
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    severity: "error",
    message:
      "Private key detected in source code. Private keys must never be " +
      "committed to version control. Use a secrets manager or file reference.",
  },

  // GitHub personal access tokens
  {
    id: "GITHUB_TOKEN",
    name: "GitHub personal access token",
    pattern: /\b(?:ghp_[a-zA-Z0-9]{20,40}|github_pat_[a-zA-Z0-9_]{20,90})\b/g,
    severity: "error",
    message:
      "GitHub personal access token detected. Use GITHUB_TOKEN environment " +
      "variable or GitHub Apps for authentication.",
  },
];

// ─── Content Extraction ────────────────────────────────────────────────────

/**
 * Extract the code content from the tool_input based on tool type.
 * Returns an array of { content, label } objects to scan.
 */
function extractContent(toolName, toolInput) {
  const contentParts = [];

  switch (toolName) {
    case "Write":
      if (toolInput.content) {
        contentParts.push({
          content: toolInput.content,
          label: toolInput.file_path || "new file",
        });
      }
      break;

    case "Edit":
      if (toolInput.new_string) {
        contentParts.push({
          content: toolInput.new_string,
          label: `edit in ${toolInput.file_path || "unknown file"}`,
        });
      }
      break;

    case "MultiEdit":
      if (Array.isArray(toolInput.edits)) {
        for (const edit of toolInput.edits) {
          if (edit.new_string) {
            contentParts.push({
              content: edit.new_string,
              label: `edit in ${toolInput.file_path || "unknown file"}`,
            });
          }
        }
      }
      break;

    default:
      if (toolInput.content) {
        contentParts.push({ content: toolInput.content, label: "content" });
      }
      if (toolInput.new_string) {
        contentParts.push({ content: toolInput.new_string, label: "new_string" });
      }
      break;
  }

  return contentParts;
}

// ─── Comment Detection ─────────────────────────────────────────────────────

/**
 * Check if a match occurs inside a comment line.
 * Reduces false positives from lines like "// avoid using eval()".
 */
function isInComment(content, matchIndex) {
  const lineStart = content.lastIndexOf("\n", matchIndex) + 1;
  const linePrefix = content.slice(lineStart, matchIndex).trimStart();

  if (
    linePrefix.startsWith("//") ||
    linePrefix.startsWith("#") ||
    linePrefix.startsWith("*") ||
    linePrefix.startsWith("<!--")
  ) {
    return true;
  }

  return false;
}

// ─── Scanning Logic ────────────────────────────────────────────────────────

/**
 * Scan content against all security patterns.
 * Returns an array of findings.
 */
function scanContent(content, label) {
  const findings = [];

  for (const rule of SECURITY_PATTERNS) {
    rule.pattern.lastIndex = 0;

    let match;
    while ((match = rule.pattern.exec(content)) !== null) {
      if (isInComment(content, match.index)) {
        continue;
      }

      const linesBeforeMatch = content.slice(0, match.index).split("\n");
      const lineNumber = linesBeforeMatch.length;

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        message: rule.message,
        matchedText: match[0].slice(0, 80),
        location: label,
        line: lineNumber,
      });
    }
  }

  return findings;
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  let rawInput = "";
  for await (const chunk of process.stdin) {
    rawInput += chunk;
  }

  if (!rawInput.trim()) {
    process.exit(0);
  }

  let inputData;
  try {
    inputData = JSON.parse(rawInput);
  } catch (err) {
    process.stderr.write(
      `Security linter: failed to parse stdin: ${err.message}\n`
    );
    process.exit(0);
  }

  const toolName = inputData.tool_name || "";
  const toolInput = inputData.tool_input || {};

  const contentParts = extractContent(toolName, toolInput);

  if (contentParts.length === 0) {
    process.exit(0);
  }

  const allFindings = [];
  for (const part of contentParts) {
    const findings = scanContent(part.content, part.label);
    allFindings.push(...findings);
  }

  const errors = allFindings.filter((f) => f.severity === "error");
  const warnings = allFindings.filter((f) => f.severity === "warning");

  if (errors.length === 0 && warnings.length === 0) {
    process.exit(0);
  }

  if (errors.length > 0) {
    const errorSummary = errors
      .map(
        (f) =>
          `  [${f.ruleId}] ${f.ruleName} (line ${f.line} in ${f.location}):\n` +
          `    Matched: ${f.matchedText}\n` +
          `    ${f.message}`
      )
      .join("\n\n");

    const warningSummary =
      warnings.length > 0
        ? "\n\nAdditional warnings:\n" +
          warnings
            .map(
              (f) =>
                `  [${f.ruleId}] ${f.ruleName} (line ${f.line}): ${f.message}`
            )
            .join("\n")
        : "";

    const decision = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason:
          `Security linter blocked this write due to ${errors.length} ` +
          `security violation(s):\n\n${errorSummary}${warningSummary}\n\n` +
          `Fix these issues before writing the file. Refer to each rule's ` +
          `message for recommended alternatives.`,
      },
    };

    process.stdout.write(JSON.stringify(decision));
    process.exit(0);
  }

  // Warnings only — allow but inject context
  if (warnings.length > 0) {
    const warningSummary = warnings
      .map(
        (f) =>
          `  [${f.ruleId}] ${f.ruleName} (line ${f.line} in ${f.location}): ${f.message}`
      )
      .join("\n");

    const decision = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext:
          `Security linter warnings (non-blocking):\n${warningSummary}\n` +
          `Consider addressing these before finalizing the code.`,
      },
    };

    process.stdout.write(JSON.stringify(decision));
    process.exit(0);
  }
}

main().catch((err) => {
  process.stderr.write(`Security linter error: ${err.message}\n`);
  process.exit(0);
});
