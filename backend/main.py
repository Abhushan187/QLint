import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}
