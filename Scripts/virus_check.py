import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    raise ValueError("VirusTotal API key not found. Make sure it's in your .env file.")

# Function to Check a file hash on VirusTotal
def check_file_hash(file_hash: str):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code ==200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        print("Scan Results:")
        for engine, count in stats.items():
            print(f"  {engine}: {count}")
    else:
        print("Error:", response.status_code, response.text)

# Function to check a URL instead of a file hash
def check_url(target_url: str):

    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}
    data = {"url": target_url}

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        scan_id = response.json().get("data", {}).get("id")
        print(f"URL submitted successfully. Scan ID: {scan_id}")
    else:
        print("Error submitting URL:", response.status_code, response.text)