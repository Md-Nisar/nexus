# Nexus AI Code-Quality & Automated Refactoring Setup

This guide documents the automated code-quality pipeline for the **Nexus** platform (Java 25 / Spring Boot 4 + Angular 21 / TypeScript).

It features a **multi-provider AI architecture** allowing automated maintenance to run on **Google Gemini** (default, ~98% cost savings), **OpenAI**, or **Anthropic Claude**.

---

## 1. Architecture & Multi-Provider Support

- **SonarQube Cloud / SonarCloud**: Single-project scan covering `nexus-backend/` (JaCoCo) and `nexus-frontend/` (Vitest lcov).
- **Interactive Triage & Safe Fix**: `/sonar-triage` and `/sonar-fix` commands available via MCP and `.claude/skills/` / `.agents/skills/`.
- **Multi-Provider Refactor Runner**: `nexus-scripts/run_ai_refactor.py` executes headless agent runs supporting:
  - **Google Gemini**: `gemini-2.5-flash` (default, fastest & lowest cost), `gemini-2.5-pro`
  - **OpenAI**: `gpt-4o-mini`, `gpt-4o`, `o3-mini`
  - **Anthropic**: `claude-3-7-sonnet`, `claude-3-5-haiku`
- **Automated Refactoring Workflow**: `.github/workflows/ai-refactor.yml` runs on a weekly cron (Monday 06:00 UTC) or manually via `workflow_dispatch`.
- **AI Guardrails CI Check**: `.github/workflows/ai-guardrails.yml` runs on all `ai/**` PRs to enforce strict safety limits:
  - Max 10 files touched
  - Max 200 total lines changed
  - Zero modifications to test files (`*Test.java`, `*IT.java`, `*.spec.ts`), database migrations, build files, or security packages
  - Provenance requirement (PR body must cite Sonar issue/rule keys)
  - No automated merging — a human must review and merge.

---

## 2. Secrets & Repository Variables

In GitHub: **Repository → Settings → Secrets and variables → Actions**

### Secrets

| Name | Description | Required For |
|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API Key | **Gemini (Default provider)** |
| `OPENAI_API_KEY` | OpenAI API Key | OpenAI provider runs |
| `ANTHROPIC_API_KEY` | Anthropic API Key | Anthropic Claude provider runs |
| `SONAR_TOKEN` | SonarCloud project analysis token | CI scan publishing |
| `SONAR_READ_TOKEN` | Read-only SonarCloud token | Candidate issue pre-filtering & triage |
| `AI_APP_ID` | GitHub App ID for `nexus-ai-bot` | Automated branch/PR creation |
| `AI_APP_PRIVATE_KEY` | GitHub App private key (full PEM content) | Automated branch/PR creation |

### Variables

| Name | Default | Purpose |
|---|---|---|
| `AI_REFACTOR_ENABLED` | `false` | **Emergency Kill Switch** — set to `true` to enable automated runs |
| `SONAR_ENABLED` | `true` | Enables SonarCloud analysis in CI |

---

## 3. GitHub App Setup (`nexus-ai-bot`)

A GitHub App is required because pull requests created using the default `GITHUB_TOKEN` **do not trigger downstream `pull_request` workflows** (which means CI tests and AI Guardrails would not run).

1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App**.
2. **Name**: `nexus-ai-bot`
3. **Repository permissions**:
   - Contents: **Read and write**
   - Pull requests: **Read and write**
   - Metadata: **Read-only**
   - All other permissions: **No access** (never grant Administration or Workflows).
4. Install the App on this repository only.
5. Generate a private key and save the App ID and PEM private key to GitHub Actions secrets (`AI_APP_ID` and `AI_APP_PRIVATE_KEY`).

---

## 4. Branch Protection Rules on `main`

In GitHub: **Settings → Branches → Add rule for `main`**:
- [x] Require a pull request before merging
- [x] Require approvals: **1**
- [x] Dismiss stale approvals when new commits are pushed
- [x] Require review from Code Owners
- [x] Require status checks to pass before merging:
  - `backend-build`
  - `frontend-build`
  - `SonarQube Analysis`
  - `AI Guardrails` (when applicable)
- [x] Block force pushes and deletions
- [x] **Do not allow bypassing the above settings** (including for admins and the bot).

---

## 5. Rollout Plan

| Phase | Milestone | Graduation Gate |
|---|---|---|
| **Phase 0** | CI + Branch Protection | Quality gate green on `main`, checks required |
| **Phase 1** | Read-only `/sonar-triage` | Triage prioritization matches engineering judgment |
| **Phase 2** | Interactive `/sonar-fix` | 5 consecutive PRs merged with zero human manual edits |
| **Phase 3** | AI Guardrails CI verification | Guardrails block a deliberate test-altering diff |
| **Phase 4** | Manual `workflow_dispatch` with Gemini (`max_issues=1`) | 3 successful manual runs producing clean PRs |
| **Phase 5** | Scheduled weekly cron | Set `AI_REFACTOR_ENABLED=true` |

---

## 6. How to Run Manually in GitHub Actions

You can trigger refactoring on-demand via the GitHub Actions UI:
1. Go to **Actions → AI Refactor (scheduled)**.
2. Click **Run workflow**.
3. Select your desired options:
   - **AI Model Provider**: `gemini` (default), `openai`, or `anthropic`
   - **Model identifier**: `gemini-2.5-flash` (or `gpt-4o-mini`, `claude-3-7-sonnet`)
   - **Max Sonar issues**: `3`
   - **Dry run**: Uncheck to create a PR, or check for simulation only.
