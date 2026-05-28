# Snyk Commander

Scan all Snyk projects in your organization for vulnerabilities and interactively open fix PRs.

## Setup

```bash
pip install -r requirements.txt
export SNYK_TOKEN=<your-snyk-pat-or-service-account-token>
```

## Usage

```bash
python -m snyk-commander
```

The tool will:

1. Authenticate with the Snyk API using your token
2. List your organizations and let you pick one (or scan all)
3. Iterate through every project, fetching vulnerability data
4. Display a summary table with severity counts and fix PR availability
5. Ask whether you want to:
   - **Open fix PRs for ALL** fixable projects at once, or
   - **Review each project** one-by-one and decide individually

## Authentication

Set `SNYK_TOKEN` to either:
- A **Personal Access Token (PAT)** from [Snyk Account Settings](https://app.snyk.io/account)
- A **Service Account Token** for CI/automation

# Snyk Commander: Project Purpose & Time-Saving Analysis

## What Does Snyk Commander Aim to Solve?

Snyk Commander is designed to streamline security vulnerability management at scale within organizations that use [Snyk](https://snyk.io) for code, dependency, and container scanning. Specifically, it solves for:

- **Bulk visibility, triage, and remediation** of vulnerabilities across all Snyk projects in an organization.
- **Efficient workflow for mass-fixing**: Triggering fix PRs (Pull Requests) en masse or selectively, reducing repetitive manual work via the Snyk UI.
- **Automated and comprehensive reporting** on vulnerabilities for audit, compliance, and tracking.
- **Handling scale and interruptions**: With robust error handling, retriable scanning, and session caching.

## Key Features

- **Organization and Project Scanning**: Authenticates to Snyk, lists organizations, scans all associated projects for vulnerabilities concurrently and robustly.
- **Fix PR Automation**: (In progress) Automates the opening of fix PRs via browser automation, mimicking what a user would do manually in the Snyk UI.
- **Interactive Triage**: Lets users review all fixable projects and either open all fix PRs at once or do it one-by-one.
- **Reporting**: Exports detailed vulnerability data in Markdown and CSV for compliance, tracking, and transparency.
- **Caching and Resume**: Caches scan results to allow for fast re-scanning or to resume interrupted sessions.
- **Interactive CLI**: Presents users with action menus after scans for simplified workflow navigation.
- **Resiliency**: Graceful retries, concurrency, and error handling to accommodate large orgs and flaky cloud infra.

## How Snyk Commander Saves Time

### For Security Engineers:
- **Unified Visibility**: One command to see all vulnerabilities org-wide, not one project at a time.
- **Automated Reporting**: Instantly generates compliance-grade reports instead of manual data collation.
- **Batch Remediation**: Fix PRs can be opened in bulk with minimal input, dramatically speeding up orchestrated cleanups.
- **Session Resumption & Caching**: Saves time on repeat scans or if work is interrupted by errors, meetings, or context switches.
- **Error Mitigation**: Handles network/API errors for you, reducing babysitting.

### For DevOps Engineers:
- **Scale-Friendly**: Concurrency ensures that scanning hundreds or thousands of projects doesn’t take all day.
- **Automation Hooks**: Can be integrated into CI/CD pipelines to automate reporting or even PR opening after Snyk scans.
- **No Manual UI Navigation**: Eliminates the need for browser tab-hopping to inspect or fix issues across projects.

### For Software Developers:
- **Self-Service Security**: Developers can use the tool to get actionable vulnerability summaries and even trigger their own fix PRs.
- **Interactive Guidance**: CLI menus ease navigation through large project lists, suggesting fixes and showing what is fixable at-a-glance.
- **Fast Feedback Loop**: Developers can get an up-to-date, org-wide security status without waiting for security teams.

---

## Summary Table

| Stakeholder       | Pain Points Snyk Commander Solves                         | Time Savings Mechanism                |
|-------------------|----------------------------------------------------------|---------------------------------------|
| Security Engineer | Manual reporting, fixing many projects, error-prone UI   | Org-wide scan/report/auto-fix PRs     |
| DevOps Engineer   | Scale, CI integration, error handling, UI friction       | Bulk scan, automation, resilience     |
| Developer         | Unaware of status, slow fixes, UI overhead, context loss | Fast CLI feedback, guided fix actions |

---

## Functionality

Snyk Commander provides the following features:

- **Authentication**: Supports Snyk Personal Access Token (PAT) or Service Account Token via the `SNYK_TOKEN` environment variable or prompt.
- **Organization Selection**: Lists all Snyk organizations accessible to your token and allows you to select one or scan all.
- **Project Scanning**: Iterates through every project in the selected organization(s), fetching vulnerability data using the Snyk API with robust retry and concurrency logic.
- **Vulnerability Summary**: Displays a detailed summary table of vulnerabilities per project, including severity counts, risk scores, and fix availability.
- **Fix PR Automation**: [**PLANNED**] Lets you trigger fix pull requests (PRs) for all fixable projects at once, or review and trigger them individually. This is done via an automated browser session (Playwright) that mimics the Snyk UI.
- **Reporting**: Generates Markdown and CSV reports listing all vulnerabilities, with details such as severity, risk score, and fix status. Reports are saved in the `reports/` directory.
- **Caching**: Caches scan results to speed up repeated runs and allows resuming from previous scans.
- **Interactive Options Menu**: After scanning, provides an interactive menu to view summaries, generate reports, trigger fix PRs, or rescan the organization.
- **Robust Error Handling**: Handles API rate limits, network errors, and failed scans with retries and user prompts.

