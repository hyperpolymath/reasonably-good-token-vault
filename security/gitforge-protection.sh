#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Git Forge Secret Protection
#
# Automatically protects secrets when using git forges
# Installs as pre-commit and pre-push hooks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Secret patterns to detect
SECRET_PATTERNS=(
    # Private keys
    "-----BEGIN.*PRIVATE KEY-----"
    "-----BEGIN RSA PRIVATE KEY-----"
    "-----BEGIN EC PRIVATE KEY-----"
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "-----BEGIN PGP PRIVATE KEY BLOCK-----"

    # API keys and tokens
    "AKIA[0-9A-Z]{16}"                    # AWS Access Key
    "ghp_[a-zA-Z0-9]{36}"                 # GitHub PAT
    "glpat-[a-zA-Z0-9\-_]{20,}"           # GitLab PAT
    "xox[baprs]-[a-zA-Z0-9-]+"            # Slack tokens
    "sk-[a-zA-Z0-9]{48}"                  # OpenAI API key
    "sq0csp-[a-zA-Z0-9\-_]{43}"           # Square OAuth

    # Database credentials
    "postgres://[^:]+:[^@]+@"
    "mysql://[^:]+:[^@]+@"
    "mongodb://[^:]+:[^@]+@"
    "redis://:[^@]+@"

    # Generic secrets
    "password[\"'\\s]*[:=][\"'\\s]*[^\"'\\s]+"
    "api_key[\"'\\s]*[:=][\"'\\s]*[^\"'\\s]+"
    "secret[\"'\\s]*[:=][\"'\\s]*[^\"'\\s]+"
    "token[\"'\\s]*[:=][\"'\\s]*[^\"'\\s]+"
)

# Files to always ignore
IGNORE_FILES=(
    "*.md"
    "*.txt"
    "*.rst"
    "LICENSE*"
    "CHANGELOG*"
    ".gitignore"
)

# Scan staged files for secrets
scan_for_secrets() {
    local found_secrets=0

    echo "[SVALINN] Scanning for secrets..."

    # Get list of staged files
    local staged_files
    staged_files=$(git diff --cached --name-only --diff-filter=ACM)

    for file in $staged_files; do
        # Skip ignored files
        local skip=0
        for pattern in "${IGNORE_FILES[@]}"; do
            if [[ "$file" == $pattern ]]; then
                skip=1
                break
            fi
        done
        [[ $skip -eq 1 ]] && continue

        # Skip binary files
        if file "$file" | grep -q "binary"; then
            continue
        fi

        # Scan for each pattern
        for pattern in "${SECRET_PATTERNS[@]}"; do
            if grep -qE "$pattern" "$file" 2>/dev/null; then
                echo "[SVALINN] POTENTIAL SECRET FOUND in $file"
                echo "  Pattern: $pattern"
                grep -nE "$pattern" "$file" | head -3
                found_secrets=1
            fi
        done
    done

    return $found_secrets
}

# Encrypt file before push
encrypt_file() {
    local file="$1"
    local key_file="${SVALINN_ENCRYPTION_KEY:-$HOME/.svalinn/forge.key}"

    if [[ ! -f "$key_file" ]]; then
        echo "[SVALINN] Encryption key not found: $key_file"
        return 1
    fi

    # Use age or sops for encryption
    if command -v age &>/dev/null; then
        age -e -i "$key_file" -o "${file}.age" "$file"
        echo "[SVALINN] Encrypted: $file -> ${file}.age"
    elif command -v sops &>/dev/null; then
        sops -e "$file" > "${file}.enc"
        echo "[SVALINN] Encrypted: $file -> ${file}.enc"
    else
        echo "[SVALINN] No encryption tool available (age or sops)"
        return 1
    fi
}

# Pre-commit hook
pre_commit() {
    echo "[SVALINN] Pre-commit secret protection check"

    if ! scan_for_secrets; then
        echo ""
        echo "[SVALINN] ERROR: Potential secrets detected!"
        echo "[SVALINN] Please review the files above and remove any secrets."
        echo ""
        echo "Options:"
        echo "  1. Remove the secrets from the files"
        echo "  2. Add the files to .gitignore"
        echo "  3. Use 'git commit --no-verify' to skip (NOT RECOMMENDED)"
        echo ""
        return 1
    fi

    echo "[SVALINN] No secrets detected."
    return 0
}

# Pre-push hook
pre_push() {
    echo "[SVALINN] Pre-push secret protection check"

    # Get the remote name and URL
    local remote="$1"
    local url="$2"

    echo "[SVALINN] Pushing to: $url"

    # Extract hostname from URL
    local hostname
    hostname=$(echo "$url" | sed -E 's|.*[@/]([^:/]+).*|\1|')

    # Check if it's an allowed forge
    local allowed_forges=("github.com" "gitlab.com" "codeberg.org" "sr.ht")
    local is_allowed=0

    for forge in "${allowed_forges[@]}"; do
        if [[ "$hostname" == *"$forge"* ]]; then
            is_allowed=1
            break
        fi
    done

    if [[ $is_allowed -eq 0 ]]; then
        echo "[SVALINN] WARNING: Pushing to non-standard forge: $hostname"
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    # Final secret scan
    if ! scan_for_secrets; then
        echo "[SVALINN] ERROR: Secrets detected before push!"
        return 1
    fi

    echo "[SVALINN] Push protection check passed."
    return 0
}

# Install hooks
install_hooks() {
    local git_dir
    git_dir=$(git rev-parse --git-dir 2>/dev/null)

    if [[ -z "$git_dir" ]]; then
        echo "Not a git repository"
        return 1
    fi

    local hooks_dir="$git_dir/hooks"
    mkdir -p "$hooks_dir"

    # Install pre-commit hook
    cat > "$hooks_dir/pre-commit" << 'EOF'
#!/bin/bash
exec "$(dirname "$0")/../../security/gitforge-protection.sh" pre-commit
EOF
    chmod +x "$hooks_dir/pre-commit"

    # Install pre-push hook
    cat > "$hooks_dir/pre-push" << 'EOF'
#!/bin/bash
exec "$(dirname "$0")/../../security/gitforge-protection.sh" pre-push "$@"
EOF
    chmod +x "$hooks_dir/pre-push"

    echo "[SVALINN] Git hooks installed successfully"
}

# Main
case "${1:-}" in
    pre-commit)
        pre_commit
        ;;
    pre-push)
        shift
        pre_push "$@"
        ;;
    install)
        install_hooks
        ;;
    scan)
        scan_for_secrets
        ;;
    encrypt)
        shift
        encrypt_file "$@"
        ;;
    *)
        echo "Usage: $0 {pre-commit|pre-push|install|scan|encrypt <file>}"
        exit 1
        ;;
esac
