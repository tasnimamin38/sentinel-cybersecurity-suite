# Git Commit Signing and Verification

## Purpose

Commit signatures provide a cryptographic link between a Git commit object and a signing key. GitHub's **Verified** badge means that GitHub validated the signature and associates the signing key with the relevant account or GitHub signing service. It does not mean that the code was reviewed, tested, or proven safe.

## Interpreting GitHub status

| GitHub status | Meaning | Response |
|:---|:---|:---|
| Verified | A supported signature is present and GitHub validated it | Confirm the signer is expected; continue normal review and CI |
| Unverified — unsigned | The commit has no cryptographic signature | Treat it as unsigned, not automatically malicious; review author, provenance, diff and CI |
| Unverified — bad/unknown signature | A signature exists but GitHub could not validate or associate it | Investigate the key, identity, signature format and commit payload before trusting it |

A signature cannot be retroactively attached to an existing commit without creating a different commit object. Rewriting shared branch history only to change badges can invalidate references, disrupt open pull requests and make review harder. Do not rewrite published history for cosmetic verification.

## Create a dedicated SSH signing key on Windows

Use a dedicated key for signing; do not reuse an SSH authentication key unless there is a deliberate key-management policy. Keep the private key on the trusted workstation, protect it with a strong passphrase, and never upload or commit the private key.

In PowerShell:

```powershell
ssh-keygen -t ed25519 -C "SENTINEL Git commit signing" -f "$env:USERPROFILE\.ssh\sentinel_commit_signing"
Get-Content "$env:USERPROFILE\.ssh\sentinel_commit_signing.pub" | Set-Clipboard
```

Choose a strong passphrase when prompted. The clipboard command copies only the **public** key.

In GitHub, open **Settings → SSH and GPG keys → New SSH key**, choose **Signing Key** as the key type, paste the public key, give it a recognizable title, and save. Do not choose Authentication Key for this signing-only key.

## Configure Git to sign future commits

Run in PowerShell:

```powershell
git config --global gpg.format ssh
git config --global user.signingkey "$env:USERPROFILE\.ssh\sentinel_commit_signing.pub"
git config --global commit.gpgsign true
```

Git's author email must be an email address verified on the GitHub account. For a passphrase-protected key, unlock it with the local SSH agent when prompted:

```powershell
ssh-add "$env:USERPROFILE\.ssh\sentinel_commit_signing"
```

On Windows, starting or configuring the OpenSSH Authentication Agent service may require an elevated PowerShell session. Do not remove the key passphrase merely to avoid that setup step.

## Verify the result

1. Make a normal test commit on a disposable feature branch or a branch already intended for review; never test by pushing directly to `main`.
2. Run `git log -1 --show-signature` locally and confirm that Git reports a good SSH signature.
3. Push the branch and open the exact commit on GitHub. Confirm that the commit page displays **Verified** and that the signer is the expected account.
4. If GitHub still shows Unverified, stop and correct the key type, registered public key, author email or signing configuration before relying on the setup.

## Repository enforcement and migration

Do not enable a repository-wide **Require signed commits** rule until the active pull-request stack and every intended merge path have been checked against that requirement. Existing unsigned commits may be blocked by a new enforcement rule even though they are not automatically malicious.

Prefer signing new commits from this point forward. For an existing unsigned change, preserve the original review evidence and use a reviewed replacement commit or a deliberate squash/rebase migration only when its impact on open pull requests, approvals, CI and branch ancestry is understood. Never claim that a rewritten commit is the same cryptographic object as the original.

## Separate application attestations from Git signatures

SENTINEL's Ed25519 assessment-evidence attestations authenticate a defined assessment digest and audit anchor. They are not Git commit signatures. A Verified Git commit does not validate the truth of scanner observations, and a valid assessment attestation does not make the source commit Verified. Both controls have distinct scope and must be described accurately.
