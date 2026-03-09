import os
import requests
import urllib3
import json
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings()

BASE_URL = "https://maplesyrup.bloodhoundenterprise.io"

COMMON_HEADERS = {
    "accept": "application/json",
    "Prefer": "wait=30",
}

# Kibana connection details
KIBANA_URL = "https://localhost:5601"
KIBANA_API_KEY = os.getenv("KIBANA_API_KEY")
DOMAIN_NAME = os.getenv("DOMAIN_NAME")


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────


def pretty(label: str, data: dict) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print("=" * 60)
    print(json.dumps(data, indent=2))


# ─────────────────────────────────────────────────────────────
# Collection 1 – "login and get self"
# ─────────────────────────────────────────────────────────────


def login() -> str:
    """POST /api/v2/login  →  returns session_token."""
    url = f"{BASE_URL}/api/v2/login"
    payload = {
        "login_method": "secret",
        "username": "alakesh.kothar@metronlabs.com",
        "secret": "m=#U7<mO4lQ7",
    }
    response = requests.post(url, json=payload, headers=COMMON_HEADERS, verify=False)
    response.raise_for_status()
    body = response.json()
    session_token = body["data"]["session_token"]
    print(f"[login] Status: {response.status_code}")
    print(f"[login] session_token: {session_token}")
    return session_token


def get_self(session_token: str) -> dict:
    """GET /api/v2/self  →  returns the current user profile."""
    url = f"{BASE_URL}/api/v2/self"
    headers = {
        **COMMON_HEADERS,
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    body = response.json()
    pretty("GET /api/v2/self", body)
    return body


# ─────────────────────────────────────────────────────────────
# Collection 2 – "whole process"
# ─────────────────────────────────────────────────────────────


def get_available_domains(session_token: str) -> dict:
    """GET /api/v2/available-domains  →  returns {domain_name: domain_id} for non-azure domains."""
    url = f"{BASE_URL}/api/v2/available-domains"
    headers = {
        **COMMON_HEADERS,
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    body = response.json()

    # Extract non-azure domains (mirrors the Hoppscotch testScript logic)
    domain_map = {}
    for item in body.get("data", []):
        if item.get("name") and item.get("id") and item.get("type") != "azure":
            domain_map[item["name"]] = item["id"]
            print(f"[available-domains] Stored: {item['name']} -> {item['id']}")

    pretty("GET /api/v2/available-domains", body)
    return domain_map


def get_available_types(
    session_token: str, domain_id: str, asset_group_tag_id: int = 1
) -> dict:
    """GET /api/v2/domains/{domain_id}/available-types  →  returns issue types for the domain."""
    url = f"{BASE_URL}/api/v2/domains/{domain_id}/available-types"
    headers = {
        **COMMON_HEADERS,
        "Authorization": f"Bearer {session_token}",
    }
    params = {"asset_group_tag_id": asset_group_tag_id}
    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()
    body = response.json()
    pretty(f"GET /api/v2/domains/{domain_id}/available-types", body)
    return body


def get_issue_details(session_token: str, finding_type: str = "T0GenericAll") -> dict:
    """GET /api/v2/findings/{finding_type}  →  returns details for a specific finding type."""
    url = f"{BASE_URL}/api/v2/findings/{finding_type}"
    headers = {
        **COMMON_HEADERS,
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    body = response.json()
    pretty(f"GET /api/v2/findings/{finding_type}", body)
    return body


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────


def logout(session_token: str) -> None:
    """POST /api/v2/logout  →  invalidates the current session."""
    url = f"{BASE_URL}/api/v2/logout"
    headers = {
        **COMMON_HEADERS,
        "Authorization": f"Bearer {session_token}",
    }
    response = requests.post(url, headers=headers, verify=False)
    print(f"\n[logout] Status: {response.status_code}")
    if response.status_code in (200, 204):
        print("[logout] Successfully logged out.")
    else:
        print(f"[logout] Unexpected response: {response.text}")


# ─────────────────────────────────────────────────────────────
# Kibana – Create Case
# ─────────────────────────────────────────────────────────────


def create_kibana_case(issue_details: dict) -> dict:
    """POST https://localhost:5601/api/cases  →  creates a Kibana case from issue details."""
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

    print(f"\n[create_kibana_case] Creating case: '{title}'")
    response = requests.post(
        f"{KIBANA_URL}/api/cases",
        json=payload,
        headers=headers,
        verify=False,
    )
    print(f"[create_kibana_case] Status: {response.status_code}")
    body = response.json()
    pretty("POST /api/cases (Kibana)", body)
    return body


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────


def main():
    print("\n" + "#" * 60)
    print("  COLLECTION 1 — login and get self")
    print("#" * 60)

    # Step 1 – Login
    session_token = login()

    # Step 2 – Get current user profile
    get_self(session_token)

    print("\n" + "#" * 60)
    print("  COLLECTION 2 — whole process")
    print("#" * 60)

    # Step 3 – Get available (non-azure) domains
    domain_map = get_available_domains(session_token)

    if not domain_map:
        print("[main] No non-azure domains found. Exiting whole-process flow.")
        return

    # Step 4 – Get available issue types for specified domain
    target_domain_name = (
        DOMAIN_NAME if DOMAIN_NAME in domain_map else next(iter(domain_map))
    )
    target_domain_id = domain_map[target_domain_name]
    print(f"\n[main] Using domain: {target_domain_name} ({target_domain_id})")

    get_available_types(session_token, target_domain_id, asset_group_tag_id=1)

    # Step 5 – Get details for a specific finding/issue type
    issue_details = get_issue_details(session_token, finding_type="T0GenericAll")

    # Step 6 – Create a Kibana case from the issue details
    print("\n" + "#" * 60)
    print("  KIBANA — Create Case")
    print("#" * 60)
    create_kibana_case(issue_details)

    # Step 7 – Logout
    print("\n" + "#" * 60)
    print("  LOGOUT")
    print("#" * 60)
    logout(session_token)


if __name__ == "__main__":
    main()
