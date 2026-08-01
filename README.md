# QLint — PQC Migration Scanner

Scan GitHub repositories for quantum-vulnerable cryptographic algorithms and get NIST PQC 2024 compliant migration reports.

## What it does

QLint scans the Python code in any public GitHub repository and detects cryptographic algorithms that will be broken (RSA, ECC, DSA, Diffie-Hellman) or weakened (AES-128, SHA-256) by quantum computers. Detection is AST-based — it parses real syntax trees instead of grepping text, so algorithm names in comments or strings never produce false positives. Every finding comes with a severity rating, the quantum attack vector, and a ready-to-use fix snippet showing the migration to the NIST-standardized post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA). The whole repository is summarized into a PQC readiness score from 0 to 100.

## Tech Stack

- **Backend:** Python 3.13, FastAPI, httpx
- **Database:** MongoDB (Motor async driver)
- **Auth:** JWT (python-jose) + bcrypt password hashing (passlib)
- **Frontend:** React 18, Vite
- **Scanner:** Python `ast` module (zero false positives from comments)
- **Standards:** NIST FIPS 203, 204, 205 (2024)

## Project Structure

```
QLint/
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── auth.py
│   ├── models.py
│   ├── routers/
│   │   ├── auth_router.py
│   │   ├── scan_router.py
│   │   └── user_router.py
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
│       ├── test_scanner_engine.py
│       ├── test_auth.py
│       └── test_routers.py
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

### MongoDB

QLint stores accounts, scan history, and the scan cache in MongoDB. It must be
running on `localhost:27017` before you start the backend.

**Windows:**

1. Download the MongoDB Community Server MSI from
   https://www.mongodb.com/try/download/community
2. Run the installer and keep **Install MongoDB as a Service** checked — this
   starts `mongod` on port 27017 automatically at boot.
3. Verify it is running:

```bash
# PowerShell
Get-Service MongoDB
# or, in Git Bash
sc query MongoDB
```

If the service is stopped, start it with `net start MongoDB` (run the terminal
as Administrator).

The `qlint` database and its indexes are created automatically on first
startup — no manual setup needed. If MongoDB is unreachable the API still
starts and anonymous scanning keeps working; accounts, history, and caching are
disabled until it comes back.

### GitHub Token

1. Go to github.com → **Settings** → **Developer Settings** → **Personal Access Tokens** → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select only the **public_repo** scope
4. Copy the token and paste it into `backend/.env`:

```
GITHUB_TOKEN=your_token_here
```

### Environment Variables

| Variable               | Default                     | Purpose                                    |
| ---------------------- | --------------------------- | ------------------------------------------ |
| `GITHUB_TOKEN`         | —                           | GitHub API access (required for scanning)  |
| `MONGODB_URI`          | `mongodb://localhost:27017` | MongoDB connection string                  |
| `JWT_SECRET`           | —                           | Signing key for access tokens — change it  |
| `JWT_ALGORITHM`        | `HS256`                     | JWT signing algorithm                      |
| `JWT_EXPIRE_MINUTES`   | `1440`                      | Token lifetime (24 hours)                  |
| `SCAN_CACHE_TTL_HOURS` | `24`                        | How long a cached scan result stays fresh  |

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
| POST   | `/scan`         | Full vulnerability scan  | Body: `{"repo_url": "https://github.com/owner/repo", "force_refresh": false}` |

Authentication is **optional** on `/scan`. Anonymous scans work as before; send
`Authorization: Bearer <token>` to attribute the scan to an account and have it
appear in that user's history.

### Auth

| Method | Endpoint         | Auth | Description                                        |
| ------ | ---------------- | ---- | -------------------------------------------------- |
| POST   | `/auth/register` | —    | Body: `{"email", "password"}` (min 8 chars) → token |
| POST   | `/auth/login`    | —    | Body: `{"email", "password"}` → token              |
| GET    | `/auth/me`       | JWT  | Current user                                       |
| POST   | `/auth/logout`   | JWT  | Client drops the token (stateless JWT)             |

### User

| Method | Endpoint                  | Auth | Description                                     |
| ------ | ------------------------- | ---- | ----------------------------------------------- |
| GET    | `/user/scans`             | JWT  | Paginated history (`page`, `limit` — max 50)    |
| GET    | `/user/scans/{id}/full`   | JWT  | Full stored report for one scan                 |
| DELETE | `/user/scans/{id}`        | JWT  | Delete one of your own scans                    |

## Scan Caching

Every completed scan is stored in the `scans` collection with an expiry of
`SCAN_CACHE_TTL_HOURS`. A repeat scan of the same repository within that window
returns the stored report with `"cached": true` plus `cached_at` and
`cache_expires_at`, skipping the GitHub API entirely. Send
`{"force_refresh": true}` (the **Re-scan** button in the UI) to bypass the cache
and run a fresh scan.

Cache keys are normalized, so `.../repo`, `.../repo/`, and `.../repo.git` all
share one entry.

## Supported Languages

| Language   | Status      | Scanner                            |
| ---------- | ----------- | ---------------------------------- |
| Python     | Available   | AST-based (zero false positives)   |
| JavaScript | Coming Soon | —                                  |
| TypeScript | Coming Soon | —                                  |
| Java       | Coming Soon | —                                  |
| Go         | Coming Soon | —                                  |

## Roadmap

- ~~F9: Auth (JWT + MongoDB), user accounts, scan history, scan caching~~ (done)
- F10: Team workspaces
- F11: Admin dashboard
- F12: GitHub OAuth
- F13: JS/TS scanning
- F14: Stripe integration
- F15: AI context-aware patches

## License

MIT
