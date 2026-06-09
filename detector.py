def get_url():
    url = input("Enter URL: ")
    return url


def check_https(url):
    if url.startswith("https://"):
        return 0, "HTTPS detected"

    return 2, "Uses HTTP instead of HTTPS"


def main():
    url = get_url()

    score, message = check_https(url)

    print("\nResult")
    print("------")
    print(f"Risk Score: {score}")
    print(f"Reason: {message}")


if __name__ == "__main__":
    main()