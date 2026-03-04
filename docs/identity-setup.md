# Identity Setup Guide

This guide explains how to configure your gitvault identity — the age identity key used to encrypt
and decrypt secrets. Choose the method that best fits your workflow and security requirements.

## Contents

- [Overview](#overview)
- [Option 1: OS Keyring (Recommended)](#option-1-os-keyring-recommended-for-developer-workstations)
- [Option 2: age Key File](#option-2-age-key-file)
- [Option 3: SSH Key File](#option-3-ssh-key-file-with-optional-passphrase)
- [Option 4: SSH Agent](#option-4-ssh-agent)
- [Option 5: Piped / FD-based (CI/CD)](#option-5-pipedfd-based-cicd)
- [Passphrase Management](#passphrase-management)
- [Security Recommendations](#security-recommendations)

---

## Overview

gitvault resolves your identity from the first source that succeeds, in this priority order:

| Priority | Source | How to use |
|----------|--------|------------|
| 0 (highest) | `--identity-stdin` flag | `echo "$KEY" \| gitvault --identity-stdin <cmd>` |
| 1 | `--identity <file>` flag | Pass a path to an age key file |
| 1b | `GITVAULT_IDENTITY_FD` env var (Unix only) | Pass the file descriptor number; key is read from the open FD |
| 2 | `GITVAULT_IDENTITY` env var | Set to a file path or a raw `AGE-SECRET-KEY-…` string |
| 3 | OS keyring | Populated by `gitvault identity create` (default) or `gitvault keyring set` |
| 4 (lowest) | SSH agent | Opt-in via `GITVAULT_SSH_AGENT=1` or a running `SSH_AUTH_SOCK` |

**Quick decision guide:**

- **Developer workstation** → [Option 1: OS Keyring](#option-1-os-keyring-recommended-for-developer-workstations)
- **Keyring unavailable / prefer files** → [Option 2: age Key File](#option-2-age-key-file)
- **Reuse existing SSH key** → [Option 3: SSH Key File](#option-3-ssh-key-file-with-optional-passphrase)
- **Team uses ssh-agent / hardware token** → [Option 4: SSH Agent](#option-4-ssh-agent)
- **CI/CD pipelines** → [Option 5: Piped / FD-based](#option-5-pipedfd-based-cicd)

> **Note:** Priority numbering above (0–4) matches the canonical reference in [README.md § Identity resolution](../README.md#identity-resolution). Priority 1 (`--identity`) and 1b (`GITVAULT_IDENTITY_FD`) are both treated as CLI-flag level; `GITVAULT_IDENTITY_FD` is preferred in CI because the key does not appear in the process environment listing.

---

## Option 1: OS Keyring (Recommended for developer workstations)

The OS keyring stores the age private key in your platform's secure credential store. The key
never touches disk unencrypted.

**Platform support:**

| Platform | Backend |
|----------|---------|
| macOS | Keychain |
| Linux | Secret Service (requires `libsecret` / `keyutils`) |
| Windows | Credential Manager |

### Setup

```bash
# Create a new age identity and store it directly in the OS keyring (default behaviour)
gitvault identity create

# Verify: print the public key of the stored identity
gitvault keyring get
```

That's it. gitvault will find the key automatically from the keyring on every subsequent command.

### Verify

```bash
# Should print your age public key (age1…)
gitvault identity pubkey
```

### Migrate an existing key file into the keyring

```bash
# Store the contents of an existing key file in the keyring
gitvault keyring set < ~/.config/gitvault/identity.age
```

### Remove from keyring

```bash
gitvault keyring delete
```

### Troubleshoot

> **Note:** On Linux, the Secret Service backend requires a running secrets daemon such as
> `gnome-keyring-daemon` or `kwallet`. If the keyring is unavailable, gitvault falls back to the
> next source in the priority chain. Install `libsecret` (Debian/Ubuntu: `apt install libsecret-1-0`)
> and ensure a secrets daemon is running.

> **Note:** In headless or container environments the OS keyring is typically unavailable. Use
> [Option 5: Piped / FD-based](#option-5-pipedfd-based-cicd) instead.

---

## Option 2: age Key File

Store the age private key in a plain file on disk. Use this when the OS keyring is unavailable or
when you prefer explicit, file-based credential management.

### Setup

```bash
# Create a new age identity and export it to a file
gitvault identity create --output ~/.config/gitvault/identity.age

# Restrict permissions — gitvault will refuse to load a world-readable key
chmod 600 ~/.config/gitvault/identity.age
```

### Configure gitvault to use the file

Point gitvault at the file using the environment variable or the CLI flag:

```bash
# Permanently (add to ~/.bashrc, ~/.zshrc, etc.)
export GITVAULT_IDENTITY=~/.config/gitvault/identity.age

# Per-command
gitvault --identity ~/.config/gitvault/identity.age identity pubkey

# Or pass the raw key string directly (not recommended — exposes the key in shell history)
export GITVAULT_IDENTITY="AGE-SECRET-KEY-1…"
```

### Verify

```bash
gitvault identity pubkey
# age1…
```

### Backup and restore

> **Warning:** Losing an age key file means losing access to all secrets encrypted to it. Back up
> the key before adding it as a recipient to any vault.

```bash
# Backup: encrypt the key file with a passphrase before storing it
age --passphrase --output identity.age.enc ~/.config/gitvault/identity.age

# Restore: decrypt the backup
age --decrypt --output ~/.config/gitvault/identity.age identity.age.enc
chmod 600 ~/.config/gitvault/identity.age
```

Alternatively, store the raw `AGE-SECRET-KEY-…` string in a password manager (e.g. 1Password,
Bitwarden) as a secure note.

> **Warning:** Never commit an age key file to a git repository. Add `*.age` and your key file path
> to `.gitignore`.

---

## Option 3: SSH Key File (with optional passphrase)

Use an existing SSH key as a gitvault age identity via the `hybrid` profile. This is useful when
you already manage SSH keys and want a single credential for both SSH access and secret decryption.

### Create a hybrid identity

```bash
# Create a hybrid SSH-compatible key and export to a file
gitvault identity create --profile hybrid --output ~/.config/gitvault/ssh-identity.age

# Restrict permissions
chmod 600 ~/.config/gitvault/ssh-identity.age

# Point gitvault at the file
export GITVAULT_IDENTITY=~/.config/gitvault/ssh-identity.age
```

### Verify

```bash
gitvault identity pubkey
```

### Passphrase handling

If the SSH key has a passphrase, gitvault will prompt interactively by default. To avoid prompts:

**Store the passphrase in the OS keyring (recommended):**

```bash
gitvault keyring set-passphrase
# You will be prompted to enter the passphrase securely

# Verify it is stored
gitvault keyring get-passphrase

# Remove it later if needed
gitvault keyring delete-passphrase
```

**Supply via environment variable (CI/automation):**

```bash
export GITVAULT_IDENTITY_PASSPHRASE="your-passphrase"
```

**Supply via file descriptor (most secure for automation):**

```bash
GITVAULT_IDENTITY_PASSPHRASE_FD=4 gitvault materialize 4<<<"$PASSPHRASE"
```

---

## Option 4: SSH Agent

Delegate identity operations to a running SSH agent. The private key never leaves the agent
process, making this suitable for hardware-backed keys (YubiKey, Secretive, 1Password SSH agent).

### Enable SSH agent support

```bash
# Enable via environment variable
export GITVAULT_SSH_AGENT=1

# gitvault will use SSH_AUTH_SOCK automatically if it is set
echo "$SSH_AUTH_SOCK"
```

> **Note:** If `SSH_AUTH_SOCK` is not set, start your agent and add your key:
> ```bash
> eval "$(ssh-agent -s)"
> ssh-add ~/.ssh/id_ed25519
> ```

### Key selection (when multiple keys are loaded)

When more than one key is loaded in the agent, select the right one by fingerprint or comment:

```bash
# Via flag
gitvault --identity-selector "my-gitvault-key" identity pubkey

# Via environment variable
export GITVAULT_IDENTITY_SELECTOR="SHA256:abc123…"
```

List loaded keys and their fingerprints:

```bash
ssh-add -l
```

### Common SSH agent setups

| Tool | Notes |
|------|-------|
| **1Password SSH agent** | Set `SSH_AUTH_SOCK` to the 1Password socket path; set `GITVAULT_SSH_AGENT=1` |
| **Secretive (macOS)** | Secretive registers as the system SSH agent; `SSH_AUTH_SOCK` is set automatically |
| **YubiKey (via `gpg-agent`)** | Ensure `gpg-agent` is running with SSH support enabled |
| **Standard `ssh-agent`** | Run `eval "$(ssh-agent -s)"` and `ssh-add` your key |

### Limitations

- The SSH agent must be running and have the key loaded before gitvault is invoked.
- In headless CI environments, prefer [Option 5](#option-5-pipedfd-based-cicd) unless your CI
  platform provides an SSH agent socket.

---

## Option 5: Piped / FD-based (CI/CD)

For CI/CD pipelines, pass the identity key without writing it to disk or exposing it in the
process environment.

### File descriptor (most secure)

Opens a dedicated FD for the key, keeping it out of `/proc/<pid>/environ`:

```bash
# Bash process substitution / here-string
GITVAULT_IDENTITY_FD=3 gitvault materialize 3<<<"$GITVAULT_KEY"

# Or with a named pipe / subshell
GITVAULT_IDENTITY_FD=3 gitvault run -- my-server 3< <(echo "$GITVAULT_KEY")
```

Store `GITVAULT_KEY` as a masked/secret CI variable (GitHub Actions secret, GitLab CI variable,
etc.) containing the raw `AGE-SECRET-KEY-…` string.

### Pipe via stdin flag

```bash
echo "$GITVAULT_KEY" | gitvault --identity-stdin materialize
```

> **Note:** `--identity-stdin` reads exactly one line from stdin and treats it as the identity key.
> Any subsequent stdin content is forwarded to the child process unchanged when using `gitvault run`.

### Environment variable (simpler, less secure)

```bash
export GITVAULT_IDENTITY="$GITVAULT_KEY"
gitvault materialize
```

> **Warning:** Setting `GITVAULT_IDENTITY` to a raw key string exposes it in the process
> environment (`/proc/<pid>/environ` on Linux). Prefer `GITVAULT_IDENTITY_FD` for sensitive
> pipelines. Set `GITVAULT_NO_INLINE_KEY_WARN=1` to suppress the inline-key warning if you
> intentionally use this method.

### GitHub Actions example

```yaml
- name: Materialize secrets
  env:
    GITVAULT_KEY: ${{ secrets.GITVAULT_IDENTITY }}
  run: |
    GITVAULT_IDENTITY_FD=3 gitvault materialize 3<<<"$GITVAULT_KEY"
```

### GitLab CI example

```yaml
materialize:
  script:
    - GITVAULT_IDENTITY_FD=3 gitvault materialize 3<<<"$GITVAULT_KEY"
  variables:
    GITVAULT_KEY: $GITVAULT_IDENTITY   # masked CI variable
```

> **See also:** [docs/cicd-recipes.md](cicd-recipes.md) for complete GitHub Actions, Docker, and Kubernetes pipeline recipes using FD-based identity passing.

---

## Passphrase Management

Applies to SSH key identities ([Option 3](#option-3-ssh-key-file-with-optional-passphrase)) that
have a passphrase protecting the private key.

### Resolution priority

gitvault resolves the SSH key passphrase from the first source that succeeds:

| Priority | Source |
|----------|--------|
| 1 (highest) | `GITVAULT_IDENTITY_PASSPHRASE_FD` — open file descriptor |
| 2 | `GITVAULT_IDENTITY_PASSPHRASE` — environment variable |
| 3 | OS keyring (stored via `gitvault keyring set-passphrase`) |
| 4 (lowest) | Interactive prompt |

### Store passphrase in the OS keyring

```bash
# Store (you will be prompted to enter the passphrase)
gitvault keyring set-passphrase

# Verify it is stored
gitvault keyring get-passphrase

# Remove
gitvault keyring delete-passphrase
```

### Use in CI without interactive prompts

```bash
# Via FD (preferred)
GITVAULT_IDENTITY_PASSPHRASE_FD=4 gitvault materialize 4<<<"$PASSPHRASE"

# Via environment variable
export GITVAULT_IDENTITY_PASSPHRASE="$PASSPHRASE"
gitvault materialize
```

Store `$PASSPHRASE` as a masked secret in your CI platform alongside the identity key.

---

## Security Recommendations

### Key handling

- **Prefer FD-passing over environment variables in CI.** File descriptors are not visible in
  `/proc/<pid>/environ` and are automatically closed on exec.
- **Never commit an identity key file** to a git repository. Add the path to `.gitignore` and
  consider adding a pre-commit hook that scans for `AGE-SECRET-KEY-` patterns.
- **Restrict key file permissions to `600`.** gitvault refuses to load a key that is readable by
  group or world.

### Backup and rotation

- **Back up your age key** before adding your public key as a vault recipient. Losing the private
  key means losing access to all secrets encrypted to it.
  - Recommended: encrypt the backup with a passphrase (`age --passphrase`) and store it in a
    password manager.
  - Alternative: store the raw `AGE-SECRET-KEY-…` string directly in your password manager as a
    secure note.
- **Rotate identities annually** or immediately after a suspected compromise:
  1. Generate a new identity: `gitvault identity create --output new-identity.age`
  2. Add the new public key as a recipient to all affected vaults.
  3. Re-encrypt secrets with `gitvault` (re-run the encryption step for each vault).
  4. Remove the old public key from the recipients file.
  5. Delete or securely erase the old key file / keyring entry.

> **Warning:** Removing a recipient key before re-encrypting secrets will permanently lock you out
> of those secrets. Always add the new key and verify access before removing the old key.

### OS keyring

- The OS keyring is the safest option for developer workstations because the key never touches
  disk unencrypted and is protected by your login credentials.
- On shared or untrusted machines, prefer piping the key via FD for each invocation rather than
  persisting it in the keyring.

### SSH agent

- Hardware-backed SSH agents (YubiKey, Secretive) provide the strongest protection because the
  private key never leaves the hardware device.
- Ensure your SSH agent socket path (`SSH_AUTH_SOCK`) is not world-writable.
