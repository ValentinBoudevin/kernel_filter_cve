#!/usr/bin/env python3
import argparse
import os
import sys
import json
import requests
import urllib.request
import urllib.error

def get_parameters():
    parser = argparse.ArgumentParser(
        description="Kernel CVE filter tool"
    )

    parser.add_argument(
        "--cve-check-input",
        required=True,
        help="Path to the CVE check input file"
    )

    parser.add_argument(
        "--kernel-path",
        required=True,
        help="Path to the kernel source or build directory"
    )

    parser.add_argument(
        "--cve-check-output",
        required=True,
        help="Path where the CVE check output will be written"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.cve_check_input):
        print(f"ERROR: CVE check input file does not exist: {args.cve_check_input}")
        sys.exit(1)

    if not os.path.isdir(args.kernel_path):
        print(f"ERROR: Kernel path is not a directory: {args.kernel_path}")
        sys.exit(1)

    git_dir = os.path.join(args.kernel_path, ".git")
    if not os.path.isdir(git_dir):
        print(f"ERROR: Kernel path is not a git repository (missing .git/): {args.kernel_path}")
        sys.exit(1)

    return args

def kernel_get_cves_unfixed(path):
    """
    Load CVE JSON input and return all CVE entries where status != 'Patched'.
    """

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: JSON missing 'package' key")
        sys.exit(1)

    unfixed = []

    for pkg in data["package"]:
        pkg_name = pkg.get("name", "")

        if pkg_name != "linux-yocto":
            continue

        for cve in pkg.get("issue", []):
            status = cve.get("status", "").strip()

            if status != "Unpatched":
                continue

            unfixed.append({
                "package": pkg_name,
                "id": cve.get("id"),
                "status": status,
                "summary": cve.get("summary"),
                "link": cve.get("link"),
                "scorev2": cve.get("scorev2"),
                "scorev3": cve.get("scorev3"),
                "scorev4": cve.get("scorev4"),
                "detail": cve.get("detail")
            })

    return unfixed

def nvd_get_cve(cve_id):
    """
    Query NVD API for a CVE and return ONLY the reference URLs.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"ERROR: Failed fetching NVD data for {cve_id}: {e}")
        return []
    data = r.json()
    urls = []
    records = data.get("vulnerabilities", [])
    for entry in records:
        cve = entry.get("cve", {})
        refs = cve.get("references", [])

        for ref in refs:
            link = ref.get("url")
            if link:
                urls.append(link)
    return urls

def main():
    args = get_parameters()
    unfixed = kernel_get_cves_unfixed(args.cve_check_input)

    print("Unfixed Kernel CVEs:")
    if not unfixed:
        print("None")
        return

    for entry in unfixed:
        print(f"- {entry['id']} (package: {entry['package']}, status: {entry['status']})")

    print("\nFetching NVD details...\n")

    for entry in unfixed:
        cve_id = entry["id"]
        print(f"{cve_id}:")
        urls = nvd_get_cve(cve_id)
        if not urls:
            print("  No URLs found.")
            continue
        for u in urls:
            print(f"  - {u}")
        print()


if __name__ == "__main__":
    main()
