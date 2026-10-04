# SIH26106 Advanced Email Threat Intelligence & Forensic Intelligence Platform

Elegant, light-theme starter implementation for SIH26106.

## Included
- Elegant React/Vite security dashboard
- Dashboard overview with KPI cards and threat distribution
- Email investigation workflow
- `.eml` parsing
- SPF/DKIM/DMARC extraction
- Sender / Reply-To mismatch detection
- URL, domain and IP extraction
- Explainable heuristic threat scoring
- Investigation findings
- Threat graph visualization
- Geographic intelligence panel (data-ready)
- Automated forensic report endpoint (HTML report)
- Sample suspicious email
- Modular architecture ready for ML, threat-intelligence APIs, PostgreSQL and Neo4j

## Run

### Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 5000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open:
- Dashboard: http://localhost:3000
- API docs: http://localhost:5000/docs

## Test
Upload:
`samples/sample_phishing.eml`

## Advanced next steps
1. Train a labeled phishing/NLP model and replace heuristic scoring.
2. Add live IP/domain/URL reputation APIs with environment variables.
3. Add PostgreSQL case persistence.
4. Add Neo4j graph persistence and campaign correlation.
5. Add safe attachment hashing/sandbox integration.
6. Add authentication/RBAC and audit logging.
7. Convert HTML forensic reports to PDF.
