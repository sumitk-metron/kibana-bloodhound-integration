import os
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings()

API_KEY = os.getenv("API_KEY")

headers = {
    "Authorization": f"ApiKey {API_KEY}",
}

response = requests.get(
    "https://localhost:5601/api/cases/_find", headers=headers, verify=False
)
print(response.json())
