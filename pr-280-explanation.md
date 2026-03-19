# Explanation of Pull Request #280 – CI/CD Modernisation & Performance Refactor

This document explains what [Pull Request #280](https://github.com/OpenReferralUK/oruk-validator/pull/280) changes, in plain language for someone who is not familiar with GitHub Actions or CI/CD pipelines.

---

## Background: What is a CI/CD pipeline?

**CI/CD** stands for **Continuous Integration / Continuous Delivery**. It is an automated process that runs every time a developer proposes a code change (a "pull request") or merges code into a main branch. The pipeline:

1. **Checks** that the code compiles and all automated tests pass.
2. **Scans** the code and the application for security vulnerabilities.
3. **Packages** the application into a deployable container (a Docker image).
4. **Releases** a new version of the software.

In GitHub, these automated processes are called **GitHub Actions** and are defined in `.yml` files stored in `.github/workflows/`.

---

## What files are changed?

| File | What it is | What changed |
|---|---|---|
| `.github/workflows/ci.yml` | The main pipeline definition | Significantly refactored – see details below |
| `.github/workflows/staging-to-main.yml` | A separate rule that blocked unsafe merges | Made redundant by the new pipeline; can now be deleted |
| `OpenReferralApi.Core/packages.lock.json` | A locked list of exact library versions | Newly added to make builds more reliable |
| `OpenReferralApi.Tests/packages.lock.json` | Same as above, for the test project | Newly added |
| `OpenReferralApi/packages.lock.json` | Same as above, for the main API project | Newly added |
| `.vscode/settings.json` | VS Code editor settings | Newly added (minor developer convenience file) |

The most important change is to `ci.yml`.

---

## The old pipeline vs the new pipeline

### Old pipeline – ~6 minutes, mostly sequential

The old pipeline ran jobs one after another in a chain:

```
[Build & Test]
      |
      ├─ [CodeQL Security Scan]  ─┐
      |                            ├─ [Docker Build & Push to Registry]
      └─ [Trivy Filesystem Scan] ─┘
                                          |
                              ├─ [Trivy Image Scan]  ─┐
                              └─ [ZAP Web Scan]       ├─ [Deploy to Staging]
                                                       └─ [Deploy to Production]
```

**Problems with this approach:**
- Docker could not start until *both* security scans finished, which meant each step waited for all previous steps even when it did not need to.
- The Docker image was pushed to the public GitHub Container Registry (GHCR) on *every* pull request, even ones that were never merged.
- Heroku was used to host the staging and production environments.

---

### New pipeline – ~3 minutes, using parallelism

The new pipeline runs security checks and Docker/application scanning at the *same time*:

```
[Branch Gate]
      |
[Build & Test]
      |
      ├─ [Security Scans (CodeQL + Trivy FS)]  ─┐
      |                                           ├─ [Final Status Check]
      └─ [Docker & DAST (Image + ZAP)]           ┘         |
                                                  [Create GitHub Release]
                                                  (only on merge to main)
```

The two middle steps run **in parallel** – simultaneously – which is why the pipeline is now roughly twice as fast.

---

## Detailed explanation of each change

### 1. Renamed the workflow

**Before:** `Unified CI/CD & Deployment`
**After:** `CI/CD Pipeline`

A cosmetic rename to better reflect what the workflow now does (it no longer handles deployment directly).

---

### 2. When the pipeline runs

**Before:** The pipeline ran when:
- A pull request was opened against `staging` or `main`
- Code was pushed directly to `staging` or `main`

**After:** The pipeline runs when:
- A pull request is opened against `staging` or `main`
- Code is pushed directly to `main` only *(pushing to staging no longer triggers an extra run, because the pull request trigger already covers it)*
- A developer manually triggers it from the GitHub website (`workflow_dispatch`)

This avoids running the pipeline twice for the same code change.

---

### 3. New: Branch Gate (Job 0)

**What it does:** Checks that any pull request targeting the `main` (production) branch has come *from* the `staging` branch. If someone tries to merge directly into `main` from a feature branch, the pipeline immediately fails with a clear error message.

**Why this matters:** The `main` branch represents production. This rule enforces the standard workflow: develop → staging → production. Previously, this check lived in a *separate* workflow file (`staging-to-main.yml`). By bringing it into the main pipeline, there is only one file to maintain.

---

### 4. Improved: Build and Test (Job 1)

This job compiles the .NET application code and runs all automated tests. The changes here are:

- **Better caching:** Previously, the pipeline used a manual, custom step to save downloaded packages between runs. Now it uses the official `setup-dotnet` action's built-in caching feature, which is simpler and more reliable. The `packages.lock.json` files (new files added in this PR) provide an exact fingerprint of which packages should be downloaded, making cache hits more consistent and restores reproducible.
- **Security improvement for code coverage:** The Codecov upload step now uses OpenID Connect (OIDC) instead of a long-lived secret token. This is a modern, more secure authentication method where GitHub and Codecov verify each other's identity without needing a stored password.
- **Resilience improvement:** If no test result files are produced, the pipeline now warns instead of silently failing.

---

### 5. Refactored: Security Scans (Job 2)

**Before:** Two separate jobs ran after the build:
- Job 2: CodeQL (a Microsoft/GitHub tool that reads source code to find bugs and security flaws)
- Job 3: Trivy filesystem scan (an open-source tool that scans the project's dependencies for known vulnerabilities)

**After:** These two scans are combined into *one* job using a **matrix strategy**. A matrix strategy means GitHub automatically creates multiple copies of the same job with different settings – in this case one copy runs CodeQL and the other runs the Trivy scan, and they run in parallel.

Both scans still report their results to the GitHub Security tab (using the SARIF format – a standard file format for security results).

The Trivy scan is also updated to use a more efficient cache location (`.trivycache` in the project directory rather than the user home directory).

---

### 6. Refactored: Docker & DAST (Job 3)

This is the biggest change. Previously, three separate jobs handled Docker and dynamic security scanning:
- Job 4: Build and push the Docker image to GitHub Container Registry (GHCR)
- Job 5: Scan the pushed image with Trivy
- Job 6: Run OWASP ZAP against the running application

**After:** All three are combined into a single job. Key differences:

- **The Docker image is no longer pushed to the registry.** Previously, the image was pushed to GHCR (a public package repository) on every pull request, even unmerged ones. Now the image is built *locally* on the CI runner (`load: true` instead of `push: true`) and used only for scanning within that same job. This avoids polluting the registry with images from draft or unmerged PRs.
- **ZAP is now run using the official ZAP GitHub Action** (`zaproxy/action-baseline`), instead of manually pulling and running the ZAP Docker container with custom shell commands. This is simpler, better maintained, and automatically creates a GitHub Issue with any findings.
- **Trivy image scan runs on the locally-built image** rather than a remotely-pushed one.
- **Cleaner start/stop lifecycle:** The application container is explicitly stopped and removed at the end of the job, keeping the runner environment clean.

---

### 7. New: Final Workflow Status / Gatekeeper (Job 4)

**What it is:** A dedicated job that waits for *both* parallel paths (security scans and Docker/DAST) to complete, then reports a single pass/fail result.

**Why it matters:** GitHub's branch protection rules require you to name specific checks that must pass before code can be merged. In the old pipeline, the repository had to list several individual job names as required checks. If any job was renamed or reorganised, those rules would break silently. Now, there is a single check – **"Final Workflow Status"** – that summarises everything. The branch protection rules only need to require this one check, making the configuration much more robust to future changes.

---

### 8. Simplified: Create GitHub Release (Job 5)

**Before:** Creating a GitHub Release was part of the "Deploy to Production" job, which also ran `heroku` commands.

**After:** The release step is its own dedicated job that:
- Only runs when code is pushed to `main` (i.e., a merge to production)
- Only runs if the Final Workflow Status check passed
- Creates a numbered release on GitHub (e.g., `v42`)

---

### 9. Removed: Heroku Deployment

The two deployment jobs ("Deploy to Staging" and "Deploy to Production") that pushed the Docker image to Heroku and ran health checks are **completely removed**. The PR description notes that Heroku is no longer being used for hosting. Deployment is now handled separately (outside of this pipeline).

---

### 10. Removed: Separate staging-to-main workflow

The file `.github/workflows/staging-to-main.yml` is now redundant because its functionality has been absorbed into the `branch-gate` job in the main `ci.yml`. The PR description recommends deleting it.

> **Important follow-up action required:** The GitHub repository's branch protection rules for `staging` and `main` must be updated to only require **"Final Workflow Status"** as the required check. If this is not done, future pull requests may be blocked by the old check names that no longer exist.

---

## Summary

| What changed | Old behaviour | New behaviour |
|---|---|---|
| Pipeline speed | ~6 minutes | ~3 minutes |
| Job structure | 8 jobs, mostly sequential | 5 jobs, key steps run in parallel |
| Branch enforcement | Separate workflow file | Built into the main pipeline |
| Docker image publishing | Pushed to GHCR on every PR | Only built locally, never pushed from PRs |
| ZAP web security scan | Manual Docker commands | Official ZAP GitHub Action |
| Heroku deployment | Deployed to staging and production | Removed entirely |
| Release creation | Combined with Heroku deployment step | Own dedicated job |
| NuGet package restore | Flexible (any compatible version) | Locked to exact versions via `packages.lock.json` |
| Single required status check | Multiple individual job names | One: "Final Workflow Status" |
