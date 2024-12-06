import re
import requests
import validators
import tldextract

# Function to validate the URL format
def validate_url(url):
    if validators.url(url):
        return True
    else:
        return False

# Function to check if the URL uses an IP address
def is_ip_url(url):
    ip_pattern = re.compile(r"^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$")
    return bool(ip_pattern.match(url))

# Function to extract domain details
def extract_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

# Heuristic-based checks for phishing
def heuristic_checks(url):
    phishing_keywords = ["login", "verify", "update", "secure", "account", "bank", "free", "gift"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True
    return False

# Function to check URL using a blacklist API
def check_blacklist(url):
    # Example with Google Safe Browsing API
    api_key = "your_google_safe_browsing_api_key"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(endpoint, headers=headers, json=payload)
    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return True  # URL is blacklisted
    return False  # URL is safe

# Main function to scan a URL
def scan_url(url):
    if not validate_url(url):
        return "Invalid URL format."

    print("Scanning URL...")
    
    if is_ip_url(url):
        return "Suspicious: URL contains an IP address instead of a domain name."

    domain = extract_domain(url)
    print(f"Domain Extracted: {domain}")

    if heuristic_checks(url):
        return "Suspicious: URL contains phishing keywords."

    if check_blacklist(url):
        return "Malicious: URL is listed in the blacklist."

    return "Safe: URL passed all checks."

# Test the scanner
if __name__ == "__main__":
    url_to_scan = input("Enter the URL to scan: ").strip()
    result = scan_url(url_to_scan)
    print(f"Scan Result: {result}")
