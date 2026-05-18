import os
from dotenv import load_dotenv
import requests

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
if VT_API_KEY is None:
    print(f"Missing API key")
    exit()

print("")
hash_value = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
hash_value_input = input(f"Paste your hash value here or press enter for test hash: ")
if not hash_value_input:
    hash_value_input = hash_value

url = f"https://www.virustotal.com/api/v3/files/{hash_value_input}"
headers = {"accept": "application/json",
           "x-apikey": VT_API_KEY
}

print("")
response = requests.get(url, headers=headers)
if response.status_code != 200:
    print(f"Status code: {response.status_code}")
    print(f"Response text: {response.text}")
    exit()
else:
    print(f"Status code: {response.status_code}")

data = response.json()

stats = data["data"]["attributes"]["last_analysis_stats"]
malicious_count = stats["malicious"]

print("")

if malicious_count > 0:
    print(f"Potentially malicious. Malicious count: {malicious_count}")
else:
    print(f"No malicious detections. Malicious count: {malicious_count}")
