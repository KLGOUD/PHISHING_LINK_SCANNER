import re
import validators
from urllib.parse import urlparse

# List of suspicious patterns
suspicious_keywords = [
    "secure", "login", "account", "verify", "payment", "banking", "prize", "support",
    "alert", "claim", "confirmation", "update", "verification", "tracking", "free"
]

# Function to check for typos or suspicious patterns
def check_for_typos(url):
    common_typos = ["0", "1", "-", "_", ".com"]
    if any(url.count(char) > 2 for char in common_typos):
        return True
    return False

# Function to check for HTTPS
def check_https(url):
    if not url.startswith("https://"):
        return True
    return False

# Function to check for suspicious domains
def check_domain(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    domain_parts = domain.split(".")
    if len(domain_parts) > 3:  # Long subdomain chains
        return True
    if any(keyword in domain for keyword in suspicious_keywords):
        return True
    return False

# Function to check for shortened URLs
def check_shortened_url(url):
    shortened_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"]
    domain = urlparse(url).netloc
    if domain in shortened_domains:
        return True
    return False

# Main function to scan the URL
def scan_url(url):
    if not validators.url(url):
        return {"status": "Invalid URL", "reason": "The input is not a valid URL."}
    
    reasons = []
    if check_for_typos(url):
        reasons.append("URL contains typos or suspicious patterns (e.g., 'g00gle' instead of 'google').")
    if check_https(url):
        reasons.append("URL does not use HTTPS (secure protocol).")
    if check_domain(url):
        reasons.append("Domain or subdomain looks suspicious.")
    if check_shortened_url(url):
        reasons.append("URL uses a shortened domain, which can obscure the actual destination.")

    if reasons:
        return {"status": "Suspicious URL", "reason": reasons}
    return {"status": "Legitimate URL", "reason": "No suspicious patterns detected."}

# User input
if __name__ == "__main__":
    print("=== Phishing URL Scanner ===")
    url = input("Enter a URL to scan: ").strip()
    result = scan_url(url)
    print(f"\nStatus: {result['status']}")
    if isinstance(result["reason"], list):
        print("Reasons:")
        for reason in result["reason"]:
            print(f"- {reason}")
    else:
        print(f"Reason: {result['reason']}")
