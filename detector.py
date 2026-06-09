from urllib.parse import urlparse
import ipaddress

def get_url():
    url = input("Enter URL: ")
    return url


def check_https(url):
    if url.startswith("https://"):
        return 0, "HTTPS detected"
    return 2, "Uses HTTP instead of HTTPS"


def check_url_length(url):
    if len(url) > 75:
        return 2, "URL is unusually long"

    return 0, "URL length appears normal"


def check_hyphens(url):
    hyphen_count = url.count("-")

    if hyphen_count > 2:
        return 1, "Multiple hyphens detected"

    return 0, "No excessive hyphens detected"


def check_keywords(url):
    suspicious_keywords = ["login","verify","update","secure","account","password","banking"]

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return 2, f"Suspicious keyword detected: {keyword}"

    return 0, "No suspicious keywords detected"

def check_ip_address(url):
    try:
        domain = urlparse(url).netloc

        if ":" in domain:
            domain = domain.split(":")[0]

        ipaddress.ip_address(domain)

        return 3, "IP address used instead of domain name"

    except ValueError:
        return 0, "Domain name detected"

def classify_risk(score):
    if score <= 2:
        return "SAFE"
    elif score <= 5:
        return "MEDIUM RISK"
    elif score <= 8:
        return "HIGH RISK"
    else:
        return "VERY HIGH RISK"


def main():
    url = get_url()

    score, message = check_https(url)
    hyphen_score, hyphen_reason = check_hyphens(url)
    length_score, length_reason = check_url_length(url)
    keyword_score, keyword_reason = check_keywords(url)
    ip_score, ip_reason = check_ip_address(url)

    total_score = (score + hyphen_score + length_score + keyword_score + ip_score)

    risk_level = classify_risk(total_score)

    print("\nResult")
    print("------")
    print(f"Risk Score: {total_score}")
    print(f"Risk Level: {risk_level}")

    print("\nReasons:")
    print(f"- {message}")
    print(f"- {hyphen_reason}")
    print(f"- {length_reason}")
    print(f"- {keyword_reason}")
    print(f"- {ip_reason}")


if __name__ == "__main__":
    main()