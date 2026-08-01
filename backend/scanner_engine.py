"""Repository scan orchestration for the PQC Migration Scanner.

Ties together github_client (fetch), ast_scanner (detect), and
vulnerability_db (score) into a single repository report.
"""

import asyncio

import httpx
from fastapi import HTTPException

from ast_scanner import scan_python_source
from github_client import (
    GitHubError,
    check_rate_limit,
    get_file_content,
    get_repo_files,
    language_for_path,
    parse_repo_url,
)
from js_scanner import scan_js_source
from vulnerability_db import get_severity_score

MAX_CONCURRENT_FETCHES = 10
MIN_RATE_LIMIT = 100

SCANNERS = {
    "python": scan_python_source,
    "javascript": scan_js_source,
    "typescript": scan_js_source,
}


def _normalize_file(entry: dict | str) -> dict[str, str]:
    """Accept either {"path", "language"} or a bare path string."""
    if isinstance(entry, str):
        return {"path": entry, "language": language_for_path(entry) or "python"}
    return {
        "path": entry["path"],
        "language": entry.get("language")
        or language_for_path(entry["path"])
        or "python",
    }


async def scan_repository(
    repo_url: str, token: str, client: httpx.AsyncClient
) -> dict:
    """Scan every .py file in a GitHub repo and build the full PQC report.

    Raises HTTPException 429 when the GitHub rate limit is nearly exhausted;
    propagates github_client errors (RepoNotFoundError, InvalidTokenError, ...)
    for the API layer to map. Individual file failures are skipped, never fatal.
    """
    owner, repo = parse_repo_url(repo_url)

    rate = await check_rate_limit(token, client=client)
    if rate["remaining"] < MIN_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=(
                f"GitHub rate limit too low: {rate['remaining']} requests "
                f"remaining. Try again after {rate['reset_at']}"
            ),
        )

    repo_files = [
        _normalize_file(entry)
        for entry in await get_repo_files(repo_url, token, client=client)
    ]

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    async def fetch(file: dict[str, str]) -> tuple[dict[str, str], str | None]:
        async with semaphore:
            try:
                content = await get_file_content(
                    owner, repo, file["path"], token, client=client
                )
            except (GitHubError, httpx.HTTPError):
                content = None  # skip this file, keep the scan alive
            return file, content

    results = await asyncio.gather(*(fetch(file) for file in repo_files))

    skipped_files: list[str] = []
    findings_by_file: dict[str, list[dict]] = {}
    all_findings: list[dict] = []
    languages_scanned: list[str] = []
    scanned_files = 0

    for file, content in results:
        path, language = file["path"], file["language"]
        if content is None:
            skipped_files.append(path)
            continue
        scanned_files += 1
        if language not in languages_scanned:
            languages_scanned.append(language)
        scanner = SCANNERS.get(language, scan_python_source)
        file_findings = [
            {"file": path, "language": language, **finding}
            for finding in scanner(content, filename=path)
        ]
        if file_findings:
            findings_by_file[path] = file_findings
            all_findings.extend(file_findings)

    severity_summary = {"critical": 0, "warning": 0, "safe": 0, "info": 0}
    for finding in all_findings:
        severity = finding["severity"]
        if severity in severity_summary:
            severity_summary[severity] += 1

    # "info" entries (e.g. bare `import hashlib`) are inspection notes,
    # not algorithms — keep them out of the algorithms list.
    algorithms_found = sorted(
        {f["algorithm"] for f in all_findings if f["severity"] != "info"}
    )

    final_rate = await check_rate_limit(token, client=client)

    return {
        "repo": f"{owner}/{repo}",
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "total_findings": len(all_findings),
        "pqc_readiness_score": get_severity_score(all_findings),
        "severity_summary": severity_summary,
        "findings_by_file": findings_by_file,
        "algorithms_found": algorithms_found,
        "languages_scanned": sorted(languages_scanned),
        "rate_limit_remaining": final_rate["remaining"],
    }
