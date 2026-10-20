#!/usr/bin/env bash
# Verify that Node.js is installed (required for the security linter hook)
set -e

if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is required for the security-linter plugin."
  echo "Install Node.js from https://nodejs.org/ or via your package manager."
  exit 1
fi

NODE_VERSION=$(node --version)
echo "Security Linter plugin: Node.js ${NODE_VERSION} detected. Ready."
exit 0
