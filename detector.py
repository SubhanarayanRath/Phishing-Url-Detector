from urllib.parse import urlparse
import ipaddress
import csv

from colorama import Fore, Style, init

init(autoreset=True)


def get_url():
    return input("Enter URL: ")


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
    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "password",
        "banking"
    ]

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return 2, f"Suspicious keyword detected: {keyword}"

    return 0, "No suspicious keywords detected"


def check_ip_address(url):
    try:
        parsed = urlparse(url)

        domain = parsed.netloc if parsed.netloc else parsed.path

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


def get_risk_color(risk_level):
    if risk_level == "SAFE":
        return Fore.GREEN
    elif risk_level == "MEDIUM RISK":
        return Fore.YELLOW
    else:
        return Fore.RED


def analyze_url(url):
    https_score, https_reason = check_https(url)
    hyphen_score, hyphen_reason = check_hyphens(url)
    length_score, length_reason = check_url_length(url)
    keyword_score, keyword_reason = check_keywords(url)
    ip_score, ip_reason = check_ip_address(url)

    total_score = (
        https_score
        + hyphen_score
        + length_score
        + keyword_score
        + ip_score
    )

    risk_level = classify_risk(total_score)

    reasons = [
        https_reason,
        hyphen_reason,
        length_reason,
        keyword_reason,
        ip_reason
    ]

    return total_score, risk_level, reasons


def export_to_csv(results):
    with open("report.csv", "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "URL",
            "Risk Score",
            "Risk Level"
        ])

        writer.writerows(results)

    print("\nReport saved as report.csv")


def scan_file(filename):
    try:
        with open(filename, "r") as file:
            urls = file.readlines()

        print("\nBatch Scan Results")
        print("-" * 60)

        results = []

        for url in urls:
            url = url.strip()

            if not url:
                continue

            score, risk_level, reasons = analyze_url(url)

            results.append([
                url,
                score,
                risk_level
            ])

            color = get_risk_color(risk_level)

            print(f"\nURL: {url}")
            print(f"Score: {score}")
            print(
                f"Risk Level: "
                f"{color}{risk_level}{Style.RESET_ALL}"
            )

        export_to_csv(results)

    except FileNotFoundError:
        print("File not found.")


def main():
    choice = input(
        "Choose an option:\n"
        "1. Scan a single URL\n"
        "2. Scan URLs from file\n\n"
        "Enter choice: "
    )

    if choice == "1":
        url = get_url()

        score, risk_level, reasons = analyze_url(url)

        color = get_risk_color(risk_level)

        print("\nResult")
        print("------")
        print(f"Risk Score: {score}")

        print(
            f"Risk Level: "
            f"{color}{risk_level}{Style.RESET_ALL}"
        )

        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")

    elif choice == "2":
        filename = input("Enter filename: ")
        scan_file(filename)

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
