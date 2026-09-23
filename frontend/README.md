# Email_sec Frontend

Professional dark SOC-style frontend prototype for the AI-powered email threat detection and forensic intelligence project.

## 1. Install
Make sure Node.js is installed, then open this folder in a terminal:

```bash
npm install
```

## 2. Run
```bash
npm run dev
```

Open the localhost address Vite gives you.

## 3. What is already included
- Dark cybersecurity/SOC visual theme
- Responsive sidebar navigation
- Threat score dashboard
- SPF/DKIM/DMARC status cards
- Explainable threat reasons
- IOC summary
- Email route/infrastructure visualisation
- `.eml` upload interface
- Analysis result flow using demo data
- Placeholder pages for Cases, IOC Explorer, Geo Intelligence, Infrastructure, Campaigns and Reports
- React + Vite structure ready for FastAPI integration

## 4. Connect the real backend
The current UI uses demo data in `src/main.jsx`.

When the backend is ready, replace the demo analysis flow with a `fetch()` call to your FastAPI endpoint, for example:

```js
const form = new FormData();
form.append("file", file);

const response = await fetch("http://localhost:8000/analyze", {
  method: "POST",
  body: form
});

const result = await response.json();
```

Then map the returned JSON fields to the dashboard components.

## 5. Suggested backend response
```json
{
  "score": 82,
  "classification": "HIGH RISK",
  "sender": "sender@example.com",
  "subject": "Example subject",
  "authentication": {
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "FAIL"
  },
  "ips": [],
  "domains": [],
  "urls": [],
  "locations": [],
  "reasons": []
}
```

## Team note
This is intentionally frontend-first. Do not claim that the placeholder modules are fully implemented until the backend/intelligence modules are connected.
