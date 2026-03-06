# Recipient Management

> **[← README](../README.md)** · [Identity Setup](identity-setup.md) · Recipient Management · [CI/CD Recipes](cicd-recipes.md) · [Seal vs Encrypt](seal-vs-encrypt.md) · [CLI Reference](reference.md)

This guide covers the full lifecycle of managing recipients in a gitvault-encrypted repository: onboarding new team members, offboarding departing ones, and rekeying secrets when the recipient set changes.

## Overview

Recipients are age public keys. Every secret in the vault is encrypted simultaneously for **all current recipients** — anyone on the list can decrypt any secret using their private identity key. When you add or remove a recipient, you must run `gitvault rekey` to re-encrypt all secrets for the updated set. Until you rekey, the encrypted files still reflect the old recipient list.

## How Recipients Work

- Each recipient has a `.pub` file in `.gitvault/recipients/` — this directory is committed to the repo.
- Secrets are encrypted once for all recipients simultaneously using age's multi-recipient feature.
- Any recipient with their private identity key can decrypt any secret — no shared secrets or passphrases.
- **Changing the recipient list requires `gitvault rekey`** to rebuild the ciphertext for every secret.

```
.gitvault/
├── recipients/
│   ├── alice.pub     ← Alice's age public key (committed)
│   ├── bob.pub       ← Bob's age public key (committed)
│   └── ci-prod.pub   ← CI service account key (committed)
└── store/
    └── prod/
        └── DATABASE_URL.age   ← encrypted for alice + bob + ci-prod
```

## Adding a New Team Member (Recommended PR Workflow)

The safest onboarding path uses a Git PR so the team can verify who is being added before rekeying.

### New member: prepare your public key

```bash
# Step 1: Create your identity (if not done yet)
gitvault identity create

# Step 2: Add yourself as a recipient (creates .gitvault/recipients/<your-name>.pub)
gitvault recipient add-self

# Step 3: Commit your public key and open a PR
git add .gitvault/recipients/
git commit -m "onboard: add alice as recipient"
git push origin alice/onboard
gh pr create --title "onboard: add alice as recipient"
```

> **Note:** Your public key is safe to commit — it's a public key, not a secret. The PR lets the team verify who is being added before rekeying.

### Maintainer: review, merge, and rekey

```bash
# Step 1: Pull the merged PR changes
git checkout main && git pull

# Step 2: Preview what will be rekeyed
gitvault rekey --dry-run

# Step 3: Rekey all secrets for the new recipient set
gitvault rekey

# Step 4: Commit the updated encrypted files
git add .gitvault/store/
git commit -m "chore: rekey secrets for alice"
git push
```

> **Security:** Only a current recipient (someone who can already decrypt) can perform the rekey — this is the zero-shared-secret property. The new member cannot decrypt until a maintainer rekeyes and pushes.

### New member: pull and verify

```bash
# Step 5: Pull the rekeyed secrets
git pull

# Step 6: Verify you can decrypt
gitvault check
gitvault materialize  # or: gitvault decrypt <file.age> --reveal
```

## Adding a Recipient Manually (without PR)

When you already have a team member's public key (e.g., they sent it out-of-band), you can add it directly:

```bash
# Get the new member's public key (they run: gitvault identity pubkey)
gitvault recipient add age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Verify the list
gitvault recipient list

# Rekey
gitvault rekey
git add .gitvault/store/ .gitvault/recipients/
git commit -m "chore: add bob as recipient and rekey"
```

## Removing a Team Member (Offboarding)

```bash
# Step 1: List current recipients to find their key
gitvault recipient list

# Step 2: Remove the recipient
gitvault recipient remove age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Step 3: Remove their .pub file from the repo
rm .gitvault/recipients/alice.pub

# Step 4: Rekey immediately (they should no longer be able to decrypt new secrets)
gitvault rekey

# Step 5: Commit
git add .gitvault/store/ .gitvault/recipients/
git commit -m "chore: offboard alice, rekey secrets"
git push
```

> **Security:** After rekeying, the removed recipient can no longer decrypt secrets encrypted after this point. However, they may still have local copies of secrets decrypted before offboarding — rotate any sensitive credentials they had access to.

> **Warning:** Always rekey immediately after removing a recipient. If you commit the recipient removal without rekeying, the encrypted files still contain ciphertext encrypted for the removed key.

## Rekeying After Multiple Changes

Batch recipient changes together and rekey once to minimise churn:

```bash
# Batch changes: add bob, remove charlie, then rekey once
gitvault recipient add age1bob...
gitvault recipient remove age1charlie...

# Preview
gitvault rekey --dry-run

# Apply
gitvault rekey
git add .gitvault/store/ .gitvault/recipients/
git commit -m "chore: rekey — add bob, remove charlie"
```

## Rekeying a Single Environment

```bash
# Only rekey prod secrets (leave dev unchanged)
gitvault rekey --env prod

# Only rekey dev secrets
gitvault rekey --env dev
```

This is useful when dev and prod have different recipient sets and you're only changing one of them.

## Checking Recipient Status

```bash
# List all current recipients
gitvault recipient list

# Full safety check (includes recipient validation)
gitvault check

# Repository status overview
gitvault status
```

## CI/CD and Automation

Rekey should only be triggered by humans (maintainers), not automated pipelines. The rekey operation requires a valid identity with decryption access — CI service accounts should be recipients but should never rekey.

```bash
# In CI — check that secrets are properly configured for current recipients
gitvault check --no-prompt --env prod

# In CI — run with current secrets (no rekey needed at runtime)
GITVAULT_IDENTITY_FD=3 gitvault run --no-prompt --env prod -- ./deploy.sh 3<<<"$KEY"
```

See [docs/cicd-recipes.md](cicd-recipes.md) for full CI/CD integration patterns.

## Team Scaling Patterns

### Small team (2–5)

- All members can rekey; any member can do onboarding.
- Simple: PR with `.pub` file, any existing member rekeyes.

### Larger team (5+)

- Designate 1–2 "key custodians" responsible for rekeying.
- Require PR approval from a custodian before merging `.pub` files.
- Consider environment separation: dev recipients ≠ prod recipients.

### Separate dev/prod recipients

```bash
# Dev environment: all developers
gitvault rekey --env dev   # after adding/removing dev recipients

# Prod environment: restricted set (senior devs, CI service account)
gitvault rekey --env prod  # after adding/removing prod recipients
```

## Security Recommendations

- **Always rekey synchronously with offboarding** — don't delay.
- **Use `--dry-run` before rekeying in prod** to verify scope.
- **Rotate credentials** after offboarding — not just rekey. The person had plaintext access and may have copied values locally.
- **Max 256 recipients** per encryption operation (age limit).
- **Keep `.gitvault/recipients/` and `.gitvault/store/` both committed** — they form a consistent set and must stay in sync.
- **Never share private identity keys** — each person has their own. Multi-recipient encryption means no sharing is ever needed.

## Troubleshooting

### "Cannot decrypt: no matching identity"

Your identity key doesn't match any of the recipients. Either:

- You haven't been added as a recipient yet (ask a maintainer to add you and rekey).
- You're using the wrong identity file (check `gitvault identity pubkey`).

### "Rekey failed: no identity"

You need to be a current recipient to rekey. If your key was removed by mistake, a remaining recipient must re-add you and rekey.

### Verifying rekey completeness

```bash
gitvault rekey --dry-run   # shows all files that will be rekeyed
gitvault check             # validates post-rekey state
```

### Machine-readable rekey output

```bash
gitvault rekey --json   # structured JSON output for scripting or audit logs
```

---

*For identity creation and key storage options, see [docs/identity-setup.md](identity-setup.md).*
*For CI/CD integration patterns, see [docs/cicd-recipes.md](cicd-recipes.md).*

## See also
- [CLI Reference — recipient](reference.md#recipient)
- [CLI Reference — rekey](reference.md#rekey)
- [Identity Setup](identity-setup.md) — creating your identity before adding yourself
- [CI/CD Recipes](cicd-recipes.md) — using secrets in pipelines after rekeying
