from datetime import datetime, timezone
import os
import re
from typing import Iterable

import requests


USER_AGENT = "CTI-Pulse/1.0 (educational threat-intelligence pipeline)"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_cve_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE), key=str.upper))


def fetch_kev() -> dict[str, dict]:
    response = requests.get(CISA_KEV_URL, timeout=30, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()
    catalog = response.json()
    return {
        item["cveID"]: {
            "due_date": item.get("dueDate", ""),
            "date_added": item.get("dateAdded", ""),
        }
        for item in catalog.get("vulnerabilities", [])
    }


def fetch_epss(cve_ids: Iterable[str]) -> dict[str, dict]:
    ids = [cve_id for cve_id in cve_ids if cve_id]
    if not ids:
        return {}
    response = requests.get(
        EPSS_URL,
        params={"cve": ",".join(ids)},
        timeout=30,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return {
        item["cve"]: {"epss": float(item["epss"]), "percentile": float(item["percentile"])}
        for item in response.json().get("data", [])
    }


def fetch_nvd(cve_id: str) -> dict:
    headers = {"User-Agent": USER_AGENT}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    response = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=30, headers=headers)
    response.raise_for_status()
    items = response.json().get("vulnerabilities", [])
    if not items:
        return {}
    cve = items[0]["cve"]
    descriptions = cve.get("descriptions", [])
    description = next(
        (item["value"] for item in descriptions if item.get("lang") == "en"),
        "",
    )
    metrics = cve.get("metrics", {})
    cvss = 0.0
    cvss_vector = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss = float(cvss_data.get("baseScore", 0) or 0)
            cvss_vector = cvss_data.get("vectorString", "")
            break
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss": cvss,
        "cvss_vector": cvss_vector,
        "published_at": cve.get("published", ""),
        "nvd_updated_at": cve.get("lastModified", ""),
    }


def find_pocs(cve_id: str, limit: int = 5) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(
        GITHUB_SEARCH_URL,
        params={"q": f'"{cve_id}" (exploit OR poc)', "sort": "stars", "order": "desc", "per_page": limit},
        timeout=30,
        headers=headers,
    )
    if response.status_code == 403:
        return []
    response.raise_for_status()
    return [
        {
            "repository": item["full_name"],
            "html_url": item["html_url"],
            "stars": int(item.get("stargazers_count", 0)),
        }
        for item in response.json().get("items", [])
    ]
