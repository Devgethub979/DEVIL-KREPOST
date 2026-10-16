# Publish DEVIL as a public GitHub repository

This release is a **prepared project archive**; it has NOT been pushed to an online GitHub account.

## Option A: GitHub web UI (no Git CLI needed)

1. Go to https://github.com/new while signed in.
2. Repository name: `DEVIL-Cyber-Intelligence`.
3. **Visibility: PUBLIC.** Do not initialize with README, .gitignore or license; this archive already includes README and .gitignore, and licensing is intentionally undecided.
4. Create the empty repository.
5. Extract the supplied `DEVIL-Cyber-Intelligence-Public-v3.1.zip` to a folder on your machine. Upload the **contents inside the project folder**, including dot-files and `.github`, using GitHub's upload-files UI.
6. Inspect the staged files *before* committing: no database, password hashes, keys, `.env`, GeoIP raw files, customer data or public VPS address.
7. Commit the files. GitHub Actions will run offline unit tests on the next push.

## Option B: Git/GitHub CLI (PowerShell)

Extract to a local folder and open PowerShell there:

```powershell
# Verify files and inspect before upload
Get-ChildItem -Force

git init -b main
git add .
git status --short
git commit -m "Initial DEVIL v3.1 source release"

# If GitHub CLI is installed and authenticated:
gh repo create DEVIL-Cyber-Intelligence --public --source=. --remote=origin --push
```

If not using `gh`, create an empty public repo via GitHub's website, then set `origin` using the URL **GitHub displays for your own new repository**:

```powershell
git remote add origin https://github.com/YOUR_USERNAME/DEVIL-Cyber-Intelligence.git
git push -u origin main
```

Never paste your real personal access token into source or Git commands visible in shell history. Use the browser/device flow or Git credential manager.

## After publishing

This is a **public source-available release**, not automatically open-source licensed. Keep `LICENSE_POLICY.md` and confirm you have permission to publish all code and any embedded geographical artwork. Configure branch protection, secret scanning, security alerts, two-factor authentication for GitHub, and never deploy unreviewed PRs to the production server.
