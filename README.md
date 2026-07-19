# QLint — PQC Migration Scanner

Scan GitHub repositories for quantum-vulnerable cryptographic algorithms and get NIST PQC 2024 compliant migration reports.

## What it does

QLint scans the Python code in any public GitHub repository and detects cryptographic algorithms that will be broken (RSA, ECC, DSA, Diffie-Hellman) or weakened (AES-128, SHA-256) by quantum computers. Detection is AST-based — it parses real syntax trees instead of grepping text, so algorithm names in comments or strings never produce false positives. Every finding comes with a severity rating, the quantum attack vector, and a ready-to-use fix snippet showing the migration to the NIST-standardized post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA). The whole repository is summarized into a PQC readiness score from 0 to 100.

## Tech Stack

- **Backend:** Python 3.13, FastAPI, httpx
- **Frontend:** React 18, Vite
- **Scanner:** Python `ast` module (zero false positives from comments)
- **Standards:** NIST FIPS 203, 204, 205 (2024)

## Project Structure

```
QLint/
├── backend/
│   ├── main.py
│   ├── github_client.py
│   ├── vulnerability_db.py
│   ├── ast_scanner.py
│   ├── scanner_engine.py
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── .env.example
│   └── tests/
│       ├── conftest.py
│       ├── test_vulnerability_db.py
│       ├── test_ast_scanner.py
│       ├── test_github_client.py
│       └── test_scanner_engine.py
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
└── README.md
```

## Setup

### Backend

```bash
cd backend
python -m venv .venv

# Windows (Git Bash):
source .venv/Scripts/activate
# Windows (PowerShell / CMD):
# .venv\Scripts\activate
# Mac / Linux:
# source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # then add your GitHub token (see below)
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

### GitHub Token

1. Go to github.com → **Settings** → **Developer Settings** → **Personal Access Tokens** → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select only the **public_repo** scope
4. Copy the token and paste it into `backend/.env`:

```
GITHUB_TOKEN=your_token_here
```

## Running Tests

```bash
cd backend
pytest
```

Expected: all tests pass.

## API Endpoints

| Method | Endpoint        | Description              | Example                                                    |
| ------ | --------------- | ------------------------ | ---------------------------------------------------------- |
| GET    | `/health`       | Health check             | Returns `{"status": "ok", "service": "PQC Migration Scanner"}` |
| GET    | `/scan/status`  | GitHub rate limit        | Returns remaining requests + reset time                    |
| POST   | `/scan/preview` | List repo Python files   | Body: `{"repo_url": "https://github.com/owner/repo"}`      |
| POST   | `/scan`         | Full vulnerability scan  | Body: `{"repo_url": "https://github.com/owner/repo"}`      |

## Supported Languages

| Language   | Status      | Scanner                            |
| ---------- | ----------- | ---------------------------------- |
| Python     | Available   | AST-based (zero false positives)   |
| JavaScript | Coming Soon | —                                  |
| TypeScript | Coming Soon | —                                  |
| Java       | Coming Soon | —                                  |
| Go         | Coming Soon | —                                  |

## Roadmap

- F9: Auth (JWT + MongoDB)
- F10: User scan history
- F11: Admin dashboard
- F12: GitHub OAuth
- F13: JS/TS scanning
- F14: Stripe integration
- F15: AI context-aware patches

## License

MIT
