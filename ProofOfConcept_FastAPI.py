import os
import hmac
import hashlib
import datetime
import base64
import requests
import urllib3
import json
import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

# Load from .env or use defaults from Bloodhound_Login.py
BASE_URL = os.getenv("BLOODHOUND_URL")
TOKEN_ID = os.getenv("BLOODHOUND_TOKEN_ID")
TOKEN_KEY = os.getenv("BLOODHOUND_TOKEN_KEY")

COMMON_HEADERS = {
    "accept": "application/json",
    "Prefer": "wait=30",
}

# Kibana connection details
KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_API_KEY = os.getenv("KIBANA_API_KEY")

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Classes for Signature Authentication
# ─────────────────────────────────────────────────────────────


class BHECredentials:
    """Stores BloodHound Enterprise API credentials."""

    def __init__(self, token_id: str, token_key: str):
        self.token_id = token_id
        self.token_key = token_key


class BloodhoundClient:
    """Client for interacting with BloodHound Enterprise API using signature authentication."""

    def __init__(self, base_url: str, credentials: BHECredentials):
        self._base_url = base_url.rstrip("/")
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        return f"{self._base_url}{uri}"

    def _request(
        self, method: str, uri: str, body: Optional[bytes] = None
    ) -> requests.Response:
        """Performs a signed request to the BHE API."""
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{uri}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        if body is not None:
            digester.update(body)

        signature = base64.b64encode(digester.digest()).decode()

        headers = {
            "User-Agent": "bhe-python-sdk 0001",
            "Authorization": f"bhesignature {self._credentials.token_id}",
            "RequestDate": datetime_formatted,
            "Signature": signature,
            "Content-Type": "application/json",
            "accept": "application/json",
            "Prefer": "wait=30",
        }

        logger.info("[BHE Request] %s %s", method, uri)
        response = requests.request(
            method=method,
            url=self._format_url(uri),
            headers=headers,
            data=body,
            verify=False,
        )
        return response

    def get_self(self) -> dict:
        response = self._request("GET", "/api/v2/self")
        response.raise_for_status()
        return response.json()

    def get_available_domains(self) -> dict:
        response = self._request("GET", "/api/v2/available-domains")
        response.raise_for_status()
        body = response.json()

        domain_map: dict[str, str] = {}
        for item in body.get("data", []):
            if item.get("name") and item.get("id") and item.get("type") != "azure":
                domain_map[item["name"]] = item["id"]
        return domain_map

    def get_available_types(self, domain_id: str, asset_group_tag_id: int = 1) -> dict:
        uri = f"/api/v2/domains/{domain_id}/available-types?asset_group_tag_id={asset_group_tag_id}"
        response = self._request("GET", uri)
        response.raise_for_status()
        return response.json()

    def get_issue_details(self, finding_type: str) -> dict:
        response = self._request("GET", f"/api/v2/findings/{finding_type}")
        response.raise_for_status()
        return response.json()

    def get_attack_path_types(self) -> dict:
        response = self._request("GET", "/api/v2/attack-path-types")
        response.raise_for_status()
        return response.json()


# ─────────────────────────────────────────────────────────────
# Global Client Instance
# ─────────────────────────────────────────────────────────────

bhe_creds = BHECredentials(TOKEN_ID, TOKEN_KEY)
bhe_client = BloodhoundClient(BASE_URL, bhe_creds)

# ─────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="BloodHound Signature PoC API",
    description=(
        "Refactored BloodHound PoC using HMAC signature authentication. "
        "Exposes BloodHound API helpers and a webhook receiver."
    ),
    version="2.0.0",
)

# ─────────────────────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────────────────────


class FindingTypeRequest(BaseModel):
    finding_type: str = "T0GenericAll"


class WebhookPayload(BaseModel):
    event_type: str | None = None
    source: str | None = None
    data: dict[str, Any] = {}


# ─────────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────────


@app.get("/", summary="Health check")
def root():
    return {
        "status": "ok",
        "service": "BloodHound Signature PoC API",
        "auth": "signature",
    }


@app.get("/self", summary="Get the current BloodHound user profile")
def get_self_endpoint():
    try:
        return bhe_client.get_self()
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


@app.get("/attack-path-types", summary="Get available attack path types")
def get_attack_path_types_endpoint():
    try:
        return bhe_client.get_attack_path_types()
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


@app.get("/domains", summary="List available (non-Azure) domains")
def get_domains_endpoint():
    try:
        return bhe_client.get_available_domains()
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


@app.get(
    "/domains/{domain_id}/available-types",
    summary="Get available issue types for a domain",
)
def get_available_types_endpoint(domain_id: str, asset_group_tag_id: int = 1):
    try:
        return bhe_client.get_available_types(domain_id, asset_group_tag_id)
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


@app.get("/findings/{finding_type}", summary="Get details for a specific finding type")
def get_issue_details_endpoint(finding_type: str):
    try:
        return bhe_client.get_issue_details(finding_type)
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


# --- Kibana -------------------------------------------------------------


def _create_kibana_case(issue_details: dict) -> dict:
    """Internal helper to create a Kibana case."""
    data = issue_details.get("data", {})
    title = data.get("title", "Untitled Case")
    tags = [data.get("type", "bloodhound")]
    description = (
        f"## Short Remediation\n\n{data.get('short_remediation', '')}\n\n"
        f"## Long Remediation\n\n{data.get('long_remediation', '')}"
    )

    payload = {
        "title": title,
        "tags": tags,
        "description": description,
        "owner": "securitySolution",
        "settings": {"syncAlerts": False},
        "connector": {
            "id": "none",
            "name": "No connector",
            "type": ".none",
            "fields": None,
        },
        "customFields": [],
    }

    headers = {
        "Authorization": f"ApiKey {KIBANA_API_KEY}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }

    logger.info("[Kibana] Creating case: %s", title)
    response = requests.post(
        f"{KIBANA_URL}/api/cases", json=payload, headers=headers, verify=False
    )
    response.raise_for_status()
    return response.json()


@app.post("/kibana/cases", summary="Create a Kibana case from issue details")
def create_kibana_case_endpoint(issue_details: dict):
    try:
        return _create_kibana_case(issue_details)
    except Exception as exc:
        logger.error("Kibana case creation failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────
# Full Workflow Endpoint
# ─────────────────────────────────────────────────────────────


@app.post("/run-full-workflow", summary="Run the full PoC workflow end-to-end")
def run_full_workflow(finding_type: str = "T0GenericAll"):
    """
    1. Get self
    2. Get available domains
    3. Get available types for first/GHOST.CORP domain
    4. Get issue details for the given finding_type
    5. Create a Kibana case
    """
    result: dict[str, Any] = {}
    try:
        result["self"] = bhe_client.get_self()
        domain_map = bhe_client.get_available_domains()
        result["domain_map"] = domain_map

        if not domain_map:
            return {"message": "No non-azure domains found.", "result": result}

        target_domain_name = (
            "GHOST.CORP" if "GHOST.CORP" in domain_map else next(iter(domain_map))
        )
        target_domain_id = domain_map[target_domain_name]
        result["target_domain"] = {"name": target_domain_name, "id": target_domain_id}
        result["available_types"] = bhe_client.get_available_types(target_domain_id)

        issue_details = bhe_client.get_issue_details(finding_type)
        result["issue_details"] = issue_details

        try:
            result["kibana_case"] = _create_kibana_case(issue_details)
        except Exception as k_exc:
            result["kibana_case_error"] = str(k_exc)

        return result
    except requests.HTTPError as exc:
        raise HTTPException(
            status_code=exc.response.status_code, detail=exc.response.text
        )


# ─────────────────────────────────────────────────────────────
# Webhook Receiver
# ─────────────────────────────────────────────────────────────

_webhook_events: list[dict] = []


def _process_webhook_event(payload: dict) -> None:
    logger.info("[webhook] Processing event: %s", json.dumps(payload, indent=2))


@app.post("/webhook", summary="Webhook receiver", status_code=202)
async def webhook_receiver(request: Request, background_tasks: BackgroundTasks):
    try:
        raw_body = await request.body()
        payload: dict = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {exc}")

    _webhook_events.append(payload)
    background_tasks.add_task(_process_webhook_event, payload)
    logger.info(
        "[webhook] Received event. Total events stored: %d", len(_webhook_events)
    )
    return {"message": "Webhook received", "queued_events": len(_webhook_events)}


@app.get("/webhook/events", summary="List received webhook events")
def list_webhook_events():
    return {"total": len(_webhook_events), "events": _webhook_events}


@app.delete("/webhook/events", summary="Clear all stored webhook events")
def clear_webhook_events():
    _webhook_events.clear()
    return {"message": "All webhook events cleared"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ProofOfConcept_FastAPI:app", host="0.0.0.0", port=8000, reload=True)
