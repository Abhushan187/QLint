import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from github_client import (
    GitHubError,
    InvalidRepoURLError,
    InvalidTokenError,
    RepoNotFoundError,
    check_rate_limit,
    get_repo_files,
    parse_repo_url,
)

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SERVICE_NAME = "PQC Migration Scanner"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Shared async client for GitHub API calls, authenticated if a token is set.
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    app.state.github = httpx.AsyncClient(
        base_url="https://api.github.com", headers=headers, timeout=30.0
    )
    yield
    await app.state.github.aclose()


app = FastAPI(title=SERVICE_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanPreviewRequest(BaseModel):
    repo_url: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/scan/preview")
async def scan_preview(request: ScanPreviewRequest):
    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN is not configured. Add it to backend/.env",
        )
    client = app.state.github
    try:
        owner, repo = parse_repo_url(request.repo_url)
        files = await get_repo_files(request.repo_url, GITHUB_TOKEN, client=client)
        rate = await check_rate_limit(GITHUB_TOKEN, client=client)
    except InvalidRepoURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except RepoNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GitHubError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"GitHub API request failed: {exc}"
        ) from exc
    return {
        "repo": f"{owner}/{repo}",
        "python_files_found": len(files),
        "files": files,
        "rate_limit_remaining": rate["remaining"],
    }
