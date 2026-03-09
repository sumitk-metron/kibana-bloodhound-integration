import hmac
import hashlib
import datetime
import base64
import requests
import json
from typing import Optional

BASE_URL = "https://maplesyrup.bloodhoundenterprise.io"
TOKEN_ID = "1ba028f8-add8-4118-b2c2-992a5e40e253"
TOKEN_KEY = "tIMK7LMjj38TDR50uTgwGWF5uTQJZ1nKZExLgTIjQve6tV0sgX3kaw=="


class BHECredentials:
    """Stores BloodHound Enterprise API credentials."""

    def __init__(self, token_id: str, token_key: str):
        self.token_id = token_id
        self.token_key = token_key


class BloodhoundClient:

    def __init__(self, base_url: str, credentials: BHECredentials):
        self._base_url = base_url.rstrip("/")
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        """Formats the full URL by joining the base URL and the URI."""
        return f"{self._base_url}{uri}"

    def _request(
        self, method: str, uri: str, body: Optional[bytes] = None
    ) -> requests.Response:

        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        digester.update(f"{method}{uri}".encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        if body is not None:
            digester.update(body)

        signature = base64.b64encode(digester.digest()).decode()

        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": signature,
                "Content-Type": "application/json",
            },
            data=body,
            verify=False,
        )

    def get_self(self) -> requests.Response:
        """GET /api/v2/self - Returns the current user profile."""
        return self._request("GET", "/api/v2/self")

    def get_available_domains(self) -> requests.Response:
        """GET /api/v2/available-domains - Returns the available domains."""
        return self._request("GET", "/api/v2/available-domains")

    def get_attack_path_types(self) -> requests.Response:
        """GET /api/v2/attack-path-types - Returns the current user permissions."""
        return self._request("GET", "/api/v2/attack-path-types")


if __name__ == "__main__":

    creds = BHECredentials(TOKEN_ID, TOKEN_KEY)
    client = BloodhoundClient(BASE_URL, creds)

    print(f"Connecting to {BASE_URL}...")
    try:
        response = client.get_available_domains()
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print("Successfully authenticated!")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")


# TODO: implement the workflow of the POC.py in the Bloodhound_Login use the bhe signature api method to communicate with the Bloodhound Enterprise API.
