# Kosty Dashboard

A single-file web dashboard to visualize Kosty AWS cost and security audit
results. It reads the JSON produced by `kosty audit --output json` and presents
an overview with two drill-down views: Security and Cost.

## Stack

- React 18 (production CDN build) + ReactDOM
- `@babel/standalone` for in-browser JSX (no build step)
- Chart.js for charts
- Tailwind CSS (CDN) and Font Awesome for styling and icons

There is no build pipeline. Open the HTML and it works.

## Quick start

1. Generate a report:
   ```bash
   kosty audit --output json
   ```
2. Serve the dashboard over HTTP so the browser can fetch the demo files:
   ```bash
   cd dashboard
   python -m http.server 8000
   # then open http://localhost:8000
   ```
   Opening `index.html` directly from the filesystem also works for uploading
   your own report; the "View Demo" buttons need HTTP because they `fetch` a
   demo file.
3. Load your report with "Load JSON Report", or click one of the demo buttons.

## Navigation

- **Overview** — the landing page after a report loads. Two large summary cards:
  - **Security**: total security findings with a critical/high/medium/low
    breakdown.
  - **Cost**: estimated monthly and annual savings, number of cost
    optimizations, and the top wasteful service.
  Click a card to open the matching view.
- **Security view** — severity stat cards, a findings-by-service bar chart, a
  severity distribution chart, and a findings grid filterable by service and
  severity. A detail modal opens on any finding.
- **Cost view** — a "Total Estimated Savings" banner, a savings-by-service chart,
  a findings grid with per-finding monthly savings, and the same filters.

Each view's stat cards, charts, and grid all reflect that view's finding type.
Use the "Back to Overview" breadcrumb to return to the landing page.

## Demo data

Two demo reports ship with the dashboard and are generated from code:

- `demo_full_audit.json` — a mixed scan (cost and security) across many services.
- `demo_ai_audit.json` — an AI-focused scan (Bedrock and SageMaker).

Both are produced by `scripts/generate_demo_dashboard.py`, which is fully offline
(no boto3, no AWS calls) and builds finding dicts in the same shape as a real
`kosty audit --output json` report. Regenerate them with:

```bash
python scripts/generate_demo_dashboard.py
```

The demo data is anonymized by construction: a fake account ID (123456789012),
generic resource names, fixed fake ARN suffixes, and a fixed neutral timestamp.

## Report shape

The dashboard consumes the `save_json_report` output:

```json
{
  "scan_timestamp": "<iso>",
  "total_issues": 0,
  "results": { "<account_id>": [ { "...finding..." } ] },
  "summary": { "total_accounts": 0, "total_issues": 0 }
}
```

Each finding carries `type` (`cost` | `security`), `severity`
(`critical` | `high` | `medium` | `low`), `Service`, `Region`, `ResourceId`,
`ResourceName`, `ARN`, `Issue`, `Risk`, `check` (the check ID), and, for cost
findings, `monthly_savings`. The cost/security split is a filter on the `type`
field; no extra report field is required.

## Accessibility

- The overview cards are keyboard-focusable buttons (Enter/Space to activate).
- Modals use `role="dialog"` with `aria-modal`, close on Escape, trap focus, and
  restore focus on close.
- Icon-only buttons have `aria-label`; decorative icons are `aria-hidden`; charts
  expose an `aria-label` text alternative.

## Deployment

Any static host works (GitHub Pages, Netlify, Vercel, S3 + CloudFront). Because
the demo buttons fetch local files, serve the `dashboard/` directory rather than
opening a lone `index.html` if you want the demos to load.
