# Project Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare the project for its first clean remote push with organized documentation, a useful README, and no committed API keys or passwords.

**Architecture:** Keep the Python Flask backend, Vue/Vite frontend, knowledge base, and utility modules in their current locations. Move loose project documents into `docs/`, replace sensitive default values with environment-driven configuration, and document the required local setup through `README.md` and `.env.example`.

**Tech Stack:** Python 3.10+, Flask, Vue 3, Vite, SQL Server/Neo4j integrations, OpenAI-compatible LLM APIs.

---

### Task 1: Configuration Secret Cleanup

**Files:**
- Create: `tests/test_config_security.py`
- Modify: `config.py`
- Modify: `utils/capture/agent_framework.py`
- Modify: `utils/detection/llm_detector.py`
- Modify: `utils/trace/LLM_Reporter.py`
- Modify: `utils/trace/main_pipeline.py`
- Modify: `utils/trace/DB_Connector.py`
- Modify: `utils/trace/app2.py`
- Modify: `utils/trace/service/traceback_service.py`

- [ ] **Step 1: Write a failing test**

Create a `unittest` check that imports `Config` with sensitive environment variables cleared and asserts default values do not contain real-looking API keys or sample passwords.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m unittest tests.test_config_security -v`
Expected before implementation: fail because `Config.LLM_API_KEY` and `Config.DB_PASSWORD` contain hardcoded values.

- [ ] **Step 3: Replace sensitive defaults**

Change defaults to environment variables with blank or local placeholder values. LLM callers should disable/skip remote calls if `LLM_API_KEY` is missing.

- [ ] **Step 4: Run the test again**

Run: `python -m unittest tests.test_config_security -v`
Expected after implementation: pass.

### Task 2: Repository Hygiene

**Files:**
- Modify: `.gitignore`
- Create: `.env.example`

- [ ] **Step 1: Update ignore rules**

Track dependency manifests but ignore generated dependency folders, virtual environments, caches, uploaded captures, generated SPA output, and local `.env` files.

- [ ] **Step 2: Add `.env.example`**

Document all runtime configuration names without real credentials.

### Task 3: Documentation Organization and README

**Files:**
- Move: `详细架构分类.md` to `docs/architecture/详细架构分类.md`
- Move: `项目文档/*` to `docs/project/*`
- Create: `README.md`

- [ ] **Step 1: Move project documents**

Keep user-facing docs under `docs/` while preserving original filenames.

- [ ] **Step 2: Write README**

Include project overview, structure, setup, environment variables, startup commands, feature modules, and security notes.

### Task 4: Verification and Push

**Commands:**
- `python -m unittest tests.test_config_security -v`
- `python -m compileall config.py utils xiaoxueqi`
- Run a repository-wide secret scan for known API-key, default-password, and internal-address patterns.
- `git status --short`
- `git add .`
- `git commit -m "chore: prepare project for clean release"`
- `git push -u origin master`

- [ ] **Step 1: Verify tests and syntax**
- [ ] **Step 2: Verify no sensitive values remain in tracked sources**
- [ ] **Step 3: Commit and push to `origin/master`**
