# Snyk Commander

Scan all Snyk projects in your organization for vulnerabilities and interactively open fix PRs.

## Setup

```bash
pip install -r requirements.txt
export SNYK_TOKEN=<your-snyk-pat-or-service-account-token>
```

## Usage

```bash
python -m snyk_commander
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

## Example Workflow

1. Authenticate with your Snyk token
2. Select an organization (or all orgs)
3. Scan all projects for vulnerabilities
4. View a summary table of vulnerabilities and fixable projects
5. Optionally trigger fix PRs (all at once or one-by-one)
6. Generate Markdown/CSV reports for audit or compliance
7. Use the interactive menu to repeat actions or exit
