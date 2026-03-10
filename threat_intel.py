import requests

API_KEY = "f215d8e9318631f17ce05c55582a1fbe9b6c47d039a15a60e9e351f407077af4d94575f3cb25315b"

def check_ip_abuse(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        data = response.json()

        score = data["data"]["abuseConfidenceScore"]

        return score

    except Exception as e:
        print("Threat Intel Error:", e)
        return 0