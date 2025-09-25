import re
import argparse
import sys
from urllib.parse import urlparse, parse_qs

# Common IDOR-related parameters to check for
IDOR_PARAMS = [
    "user_id", "account_id", "document_id", "file_id",
    "file_name", "file_path", "id",
    "userId", "thread_id", "msg_id",
    "export_id", "report_id", "job_id",
    "token"
]


def check_idor_params(urls):
    results = {}
    total = len(urls)
    for idx, url in enumerate(urls, start=1):
        parsed = urlparse(url.strip())
        query_params = parse_qs(parsed.query)

        # Collect suspicious params found in URL query string
        suspicious = [p for p in query_params if p in IDOR_PARAMS]

        # Check path for suspicious keywords
        path_suspicious = [p for p in IDOR_PARAMS if re.search(rf"[/?&]{p}[=/]", parsed.path)]

        # Merge unique findings
        findings = list(set(suspicious + path_suspicious))
        if findings:
            results[url] = findings

        # Update progress bar
        progress = int((idx / total) * 50)  # 50 chars wide
        bar = "#" * progress + "-" * (50 - progress)
        sys.stdout.write(f"\r[{bar}] {idx}/{total} URLs processed")
        sys.stdout.flush()

    print()  # Newline after progress bar
    return results


def load_urls_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return []


def save_findings_to_file(filepath, findings):
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            if findings:
                f.write("Possible IDOR parameters found:\n")
                for url, params in findings.items():
                    f.write(f"- {url}\n")
                    for p in params:
                        f.write(f"   -> {p}\n")
            else:
                f.write("No suspicious parameters found.\n")
        print(f"[+] Results saved to {filepath}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check URLs for possible IDOR parameters.")
    parser.add_argument("-f", "--file", required=True, help="Path to file containing URLs (one per line)")
    parser.add_argument("-o", "--output", help="Path to output file to save results")
    args = parser.parse_args()

    endpoints = load_urls_from_file(args.file)

    if not endpoints:
        print("[!] No URLs to check.")
        exit(1)

    findings = check_idor_params(endpoints)

    if findings:
        print("Possible IDOR parameters found:")
        for url, params in findings.items():
            print(f"- {url}")
            for p in params:
                print(f"   -> {p}")
    else:
        print("No suspicious parameters found.")

    if args.output:
        save_findings_to_file(args.output, findings)
