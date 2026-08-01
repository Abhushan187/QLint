# QLint — PQC Migration Scanner

Scan GitHub repositories for quantum-vulnerable cryptographic algorithms and get NIST PQC 2024 compliant migration reports.

## What it does

QLint scans the Python, JavaScript, and TypeScript code in any public GitHub repository and detects cryptographic algorithms that will be broken (RSA, ECC, DSA, Diffie-Hellman) or weakened (AES-128, SHA-256) by quantum computers. Python detection is AST-based — it parses real syntax trees instead of grepping text, so algorithm names in comments or strings never produce false positives. JavaScript and TypeScript have no stdlib parser to lean on, so they are scanned with context-aware patterns that strip comments and string noise before matching. Every finding comes with a severity rating, the quantum attack vector, and a ready-to-use fix snippet showing the migration to the NIST-standardized post-quantum replacement (ML-KEM, ML-DSA, SLH-DSA). The whole repository is summarized into a PQC readiness score from 0 to 100.

## Tech Stack

- **Backend:** Python 3.13, FastAPI, httpx
- **Database:** MongoDB (Motor async driver)
- **Auth:** JWT (python-jose) + bcrypt password hashing (passlib)
- **Frontend:** React 18, Vite
- **Scanners:** Python `ast` module; context-aware pattern matching for JS/TS
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
│   │   ├── admin_router.py
│   │   ├── auth_router.py
│   │   ├── oauth_router.py
│   │   ├── scan_router.py
│   │   └── user_router.py
│   ├── github_client.py
│   ├── vulnerability_db.py
│   ├── ast_scanner.py
│   ├── js_scanner.py
│   ├── scanner_engine.py
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── .env.example
│   └── tests/
│       ├── conftest.py
│       ├── test_vulnerability_db.py
│       ├── test_ast_scanner.py
│       ├── test_js_scanner.py
│       ├── test_github_client.py
│       ├── test_scanner_engine.py
│       ├── test_auth.py
│       ├── test_routers.py
│       ├── test_admin.py
│       └── test_oauth.py
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

Open http://localhost:5174 in your browser.

### GitHub OAuth App

Needed for the **Connect GitHub** and **Continue with GitHub** buttons.

1. Go to github.com -> **Settings** -> **Developer Settings** -> **OAuth Apps**
   -> **New OAuth App**
2. Application name: `QLint`
3. Homepage URL: `http://localhost:5174`
4. Authorization callback URL: `http://localhost:8000/auth/github/callback`
5. Click **Register application**
6. Copy the **Client ID** into `GITHUB_CLIENT_ID` in `backend/.env`
7. Click **Generate a new client secret** and copy it into `GITHUB_CLIENT_SECRET`
8. Restart uvicorn

The frontend dev server is pinned to port 5174 (`frontend/vite.config.js`) so
the callback URL always matches.

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
| `ADMIN_SECRET`         | —                           | Shared secret for the one-time admin bootstrap |
| `GITHUB_CLIENT_ID`     | —                           | GitHub OAuth app client ID                 |
| `GITHUB_CLIENT_SECRET` | —                           | GitHub OAuth app client secret             |
| `GITHUB_OAUTH_REDIRECT_URI` | `http://localhost:8000/auth/github/callback` | Must match the OAuth app callback |
| `FRONTEND_URL`         | `http://localhost:5174`     | Where the OAuth callback sends the browser |

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
| POST   | `/scan/preview` | List scannable source files | Body: `{"repo_url": "https://github.com/owner/repo"}`   |
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

### GitHub OAuth

| Method | Endpoint                   | Auth | Description                                  |
| ------ | -------------------------- | ---- | -------------------------------------------- |
| GET    | `/auth/github/login`       | —    | Redirects to GitHub's consent screen         |
| GET    | `/auth/github/callback`    | —    | Exchanges the code, then redirects to the frontend with a JWT |
| GET    | `/auth/github/disconnect`  | JWT  | Clears the stored OAuth token                |

Connecting GitHub stores that user's OAuth token on their account. `POST /scan`
then picks a credential in this order:

1. `github_token` in the request body (a token pasted into the form)
2. the signed-in user's connected GitHub account
3. `GITHUB_TOKEN` from the environment

So a user with GitHub connected never has to paste a token. Signing in through
GitHub also works for brand new accounts: they are created with no password and
can only sign in through GitHub afterwards.

### Admin

Every `/admin` route requires a valid token belonging to an account with
`role: "admin"`, and returns **403 Admin access required** otherwise.

| Method | Endpoint             | Auth   | Description                                    |
| ------ | -------------------- | ------ | ---------------------------------------------- |
| POST   | `/admin/make-admin`  | secret | Bootstrap: `{"email", "secret"}` promotes an account |
| GET    | `/admin/stats`       | admin  | Usage totals, top repos/users/algorithms       |
| GET    | `/admin/users`       | admin  | Paginated user list (`page`, `limit` — max 100) |
| GET    | `/admin/scans`       | admin  | Paginated scan list across all users           |
| DELETE | `/admin/users/{id}`  | admin  | Delete a user and all their scans              |

New accounts are created with `role: "user"`. Grant yourself admin once, using
the `ADMIN_SECRET` from `backend/.env`:

```bash
curl -X POST http://localhost:8000/admin/make-admin -H "Content-Type: application/json" -d '{"email": "you@example.com", "secret": "your_admin_secret"}'
```

`/admin/make-admin` is deliberately unauthenticated — it is the only way to
create the first admin — but it is useless without the secret. An admin cannot
delete their own account.

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

| Language   | Status      | Extensions       | Scanner                            |
| ---------- | ----------- | ---------------- | ---------------------------------- |
| Python     | Available   | `.py`            | AST-based (zero false positives)   |
| JavaScript | Available   | `.js`, `.jsx`    | Context-aware pattern matching     |
| TypeScript | Available   | `.ts`, `.tsx`    | Context-aware pattern matching     |
| Java       | Coming Soon | —                | —                                  |
| Go         | Coming Soon | —                | —                                  |
| Rust       | Coming Soon | —                | —                                  |

A scan report lists every language it touched under `languages_scanned`, and
each finding carries a `language` field.

### JavaScript / TypeScript detection

`js_scanner.py` covers Node `crypto` (createSign/createVerify, createHash,
createCipheriv, createECDH, createDiffieHellman), node-forge, the Web Crypto
`{ name: ... }` algorithm objects, JOSE/JWT algorithm identifiers
(RS/PS/ES/HS/EdDSA), and common libraries (NodeRSA, jsrsasign, elliptic,
@noble). Before any pattern runs, a scanner pass blanks out `//` comments,
`/* */` blocks, and template literals while preserving byte offsets, so a
`// TODO: replace RSA` note never becomes a finding and a URL inside a string
is never mistaken for a comment.

**Note on Ed25519:** QLint classifies Ed25519 and EdDSA as **critical**. Ed25519
is EdDSA over Curve25519 — an elliptic-curve scheme — so Shor's Algorithm breaks
it just as it breaks ECDSA, despite Ed25519 being strong against classical
attacks.

## Roadmap

- ~~F9: Auth (JWT + MongoDB), user accounts, scan history, scan caching~~ (done)
- ~~F11: Admin dashboard~~ (done)
- ~~F12: GitHub OAuth~~ (done)
- F10: Team workspaces
- F13: JS/TS scanning
- F14: Stripe integration
- F15: AI context-aware patches

## License

MIT
