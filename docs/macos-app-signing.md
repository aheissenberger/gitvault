# macOS Developer ID Signing Certificate Setup

This guide explains how to create a second macOS Developer ID signing certificate and configure it as GitHub Actions secrets for the gitvault release pipeline. Follow these steps on a macOS machine with Apple Developer account access.

## On your Mac (generate a CSR)

1. Open **Keychain Access**.
2. In the menu bar: **Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority…**
3. Enter your Apple Developer email address and a name.
4. Select **Saved to disk** (do not send directly to the CA).
5. Save the file as `developer-id-second.csr`.

## In the Apple Developer portal (create the second certificate)

1. Go to [developer.apple.com](https://developer.apple.com) → **Certificates, Identifiers & Profiles**.
2. Open **Certificates** and click **+**.
3. Select **Developer ID Application**.
4. Upload the `developer-id-second.csr` file you just created.
5. Download the new certificate (`.cer` file).

## Back on your Mac (install and verify)

1. Double-click the `.cer` file to import it into Keychain Access.
2. In **Login → My Certificates**, verify:
   - The new **Developer ID Application: ...** entry is visible.
   - A **private key** is nested beneath it (this is required).
3. List available signing identities:

```bash
security find-identity -v -p codesigning
```

## Export for GitHub Actions

1. In Keychain Access: right-click the new certificate (with its key) → **Export…**
2. Choose format: **Personal Information Exchange (.p12)**.
3. Then generate the Base64-encoded string:

```bash
base64 -i developer-id-signing-2.p12 | tr -d '\n' > developer-id-signing-2.p12.b64
```

4. Set the new secrets (e.g. `MACOS_CERTIFICATE_P12_BASE64`, `MACOS_CERTIFICATE_PASSWORD`, `MACOS_SIGNING_IDENTITY`) in your GitHub repository settings.

## Important

- The value for `MACOS_SIGNING_IDENTITY` must exactly match one line from the output of `security find-identity`.
- If Apple reports that the certificate limit has been reached: revoke an old, unused Developer ID certificate and create a new one.
