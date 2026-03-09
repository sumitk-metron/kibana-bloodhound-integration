import requests
import json

# --- YOUR CREDENTIALS ---
TOKEN_ID = "1ba028f8-add8-4118-b2c2-992a5e40e253"
BASE_URL = "https://maplesyrup.bloodhoundenterprise.io"


def main():
    # 1. Login
    login_url = f"{BASE_URL}/api/v2/login"
    login_headers = {
        "accept": "application/json",
        "Prefer": "wait=30",
        "Content-Type": "application/json",
    }
    login_data = {
        "login_method": "secret",
        "username": "alakesh.kothar@metronlabs.com",
        "secret": "Zodaic@123456",
    }

    print("--- Attempting Login ---")
    login_response = requests.post(login_url, headers=login_headers, json=login_data)
    print(f"Login Status Code: {login_response.status_code}")

    if login_response.status_code == 200:
        login_json = login_response.json()
        print("Login successful.")

        # Extract token from response
        # Using .get() for safety; trying common locations for session token
        token = login_json.get("data", {}).get("session_token") or login_json.get(
            "session_token"
        )

        if not token:
            print("Login response structure (to debug token location):")
            print(json.dumps(login_json, indent=2))
            return

        # 2. Get Self
        self_url = f"{BASE_URL}/api/v2/self"
        self_headers = {
            "accept": "application/json",
            "Prefer": "wait=30",
            "Authorization": f"Bearer {token}",
        }

        print("\n--- Fetching Self Information ---")
        self_response = requests.get(self_url, headers=self_headers)
        print(f"Self Status Code: {self_response.status_code}")

        try:
            print(json.dumps(self_response.json(), indent=2))
        except requests.exceptions.JSONDecodeError:
            print("Failed to decode JSON from /self. Raw response:")
            print(self_response.text)
    else:
        print("Login failed.")
        print(f"Response: {login_response.text}")


if __name__ == "__main__":
    main()
