# PQC Migration Scanner

A developer tool that scans GitHub repositories for quantum-vulnerable cryptographic algorithms and suggests NIST PQC 2024 replacements.

## Backend Setup

```bash
cd backend
python -m venv .venv
# Windows (Git Bash):
source .venv/Scripts/activate
# Windows (PowerShell/CMD):
# .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # then add your GitHub token
uvicorn main:app --reload --port 8000
```

The API is now available at http://localhost:8000 — verify with:

```bash
curl http://localhost:8000/health
```

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — the page shows "Backend connected" when the backend is running.
