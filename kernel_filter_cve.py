#!/usr/bin/env python3

import argparse
import os
import sys
import json
import requests
import subprocess
import re
import time

GIT_KERNEL_ORG_PATH = os.getcwd() + "/linux"

def get_parameters():
    parser = argparse.ArgumentParser(
        description="Kernel CVE filter tool"
    )

    parser.add_argument(
        "--cve-check-input",
        required=True,
        help="Path to the cve-check input file"
    )

    parser.add_argument(
        "--kernel-path",
        required=True,
        help="Path to the kernel source or build directory"
    )

    parser.add_argument(
        "--output-path",
        required=True,
        help="Path where the output cve-check and the kernel_remaining_cves file will be written"
    )

    parser.add_argument(
        "--nvd-api-key",
        required=True,
        help="NVD API key used for authenticated requests"
    )

    parser.add_argument(
        "--config-path",
        required=True,
        help="Path to a defconfig file used to generate a temporary .config"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="If present, print extra logs details"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="If present, load enabled_cves from existing output and skip scanning"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.cve_check_input):
        print(f"ERROR: CVE check input file does not exist: {args.cve_check_input}")
        sys.exit(1)

    if not os.path.isdir(args.kernel_path):
        print(f"ERROR: Kernel path is not a directory: {args.kernel_path}")
        sys.exit(1)
    
    if not os.path.isfile(args.config_path):
        print(f"ERROR: .config file does not exist: {args.config_path}")
        sys.exit(1)

    git_dir = os.path.join(args.kernel_path, ".git")
    if not os.path.isdir(git_dir):
        print(f"ERROR: Kernel path is not a git repository (missing .git/): {args.kernel_path}")
        sys.exit(1)

    if not args.nvd_api_key.strip():
        print("ERROR: NVD API key cannot be empty")
        sys.exit(1)

    return args

def kernel_get_cves_unfixed(path):
    """
    Load CVE JSON input and return all CVE entries where status is 'Unpatched'.
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

def nvd_get_cve(cve_id, api_key, max_retries=5, retry_wait=1):
    """
    Query NVD API for a CVE and return ONLY the reference URLs.
    Retries on HTTP 429 (rate limit).
    """
    headers = {
        "Content-Type": "application/json"
    }
    if api_key:
        headers["apiKey"] = api_key

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 429:
                if attempt < max_retries:
                    print(f"429 Too Many Requests for {cve_id}. "
                          f"Retrying {attempt}/{max_retries} in {retry_wait}s...")
                    time.sleep(retry_wait)
                    continue
                else:
                    print(f"ERROR: Max retries reached for {cve_id}. Skipping...")
                    return []
            r.raise_for_status()
            break

        except requests.HTTPError as e:
            print(f"ERROR: Failed fetching NVD data for {cve_id}: {e}")
            return []

        except Exception as e:
            print(f"ERROR: Unexpected failure fetching {cve_id}: {e}")
            return []

    try:
        data = r.json()
    except ValueError:
        print(f"ERROR: Failed to parse JSON for {cve_id}")
        return []

    urls = []
    records = data.get("vulnerabilities", [])

    for entry in records:
        refs = entry.get("cve", {}).get("references", [])
        for ref in refs:
            if ref.get("url"):
                urls.append(ref["url"])

    return urls

def kernel_filter_git_kernel_org(all_nvd_results):
    """
    Given a dict: { cve_id: [url1, url2, ...] }
    return dict of only CVEs containing a git.kernel.org stable URL.
    """
    match = {}

    for cve_id, urls in all_nvd_results.items():
        for u in urls:
            if u.startswith("https://git.kernel.org/stable/"):
                match[cve_id] = urls
                break

    return match

def kernel_clone_git_kernel_org(path):
    """
    Clone the Linux stable repository from kernel.org if it doesn't exist,
    or update it if it already exists.
    """
    repo_url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    branch = "master"

    if not os.path.exists(path):
        print(f"Cloning Linux stable repo into {path}...")
        try:
            subprocess.run(
                ["git", "clone", "--branch", branch, repo_url, path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print("Clone completed.")
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to clone repo: {e.stderr.strip()}")
    else:
        print(f"Linux stable repo already exists at {path}, updating...")
        try:
            subprocess.run(
                ["git", "-C", path, "fetch", "--all"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            subprocess.run(
                ["git", "-C", path, "reset", "--hard", f"origin/{branch}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print("Update completed.")
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to update repo: {e.stderr.strip()}")

def kernel_get_modified_files(path, git_cve_results):
    """
    Given { cve_id: [url1, url2, ...] } for URLs pointing to git.kernel.org,
    return { cve_id: [file1, file2, ...] } representing files modified by the commits.
    Skip CVE entirely if any commit SHA fails.
    """
    modified_files = {}

    for cve_id, urls in git_cve_results.items():
        files_for_cve = set()
        failed = False

        for url in urls:
            if url.startswith("https://git.kernel.org/stable/c/"):
                commit_sha = url.rstrip("/").split("/")[-1]
                try:
                    result = subprocess.run(
                        ["git", "-C", path, "show", "--name-only", "--pretty=", commit_sha],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=True
                    )
                    for f in result.stdout.splitlines():
                        f = f.strip()
                        if f:
                            files_for_cve.add(f)
                except subprocess.CalledProcessError as e:
                    print(f"ERROR: Failed to get files for commit {commit_sha} ({cve_id}): {e.stderr.strip()}")
                    failed = True
                    break
        if not failed and files_for_cve:
            modified_files[cve_id] = sorted(files_for_cve)

    return modified_files

def _parse_makefile_objects(makefile_path):
    """
    Parse a kernel Makefile and return a reverse mapping:
        object_or_folder → CONFIG_* option

    Supports lines such as:
        obj-$(CONFIG_X) += foo.o
        obj-$(CONFIG_X) += foo/ bar.o
    """
    obj_to_config = {}
    pattern = re.compile(
        r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*(.+)'
    )
    try:
        with open(makefile_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = pattern.match(line)
                if not m:
                    continue
                config, rhs = m.groups()
                entries = [tok.strip() for tok in rhs.split()]
                for e in entries:
                    obj_to_config[e] = config

    except FileNotFoundError:
        return {}

    return obj_to_config

def kernel_find_defconfig_arguments(kernel_path, modified_files_results):
    """
    Given a dict { cve_id: [file1, file2, ...] } and the kernel path,
    find the CONFIG_* defconfig option controlling each modified file.
    
    Returns a dict:
    {
        cve_id: {
            file1: CONFIG_XXX,
            file2: CONFIG_YYY,
            ...
        }
    }
    """
    result = {}
    for cve_id, files in modified_files_results.items():
        result[cve_id] = {}
        for f in files:
            dir_path = os.path.dirname(os.path.join(kernel_path, f))
            basename = os.path.basename(f).replace(".c", ".o")
            while dir_path and dir_path.startswith(kernel_path):
                makefile = os.path.join(dir_path, "Makefile")
                if os.path.isfile(makefile):
                    obj_map = _parse_makefile_objects(makefile)
                    found = obj_map.get(basename)
                    if found:
                        result[cve_id][f] = found
                        break
                folder_name = os.path.basename(dir_path)
                basename = folder_name + "/"
                dir_path = os.path.dirname(dir_path)
            else:
                result[cve_id][f] = None
    return result

def kernel_defconfig_comparaison(origin_config, defconfig_affected):
    """
    Compare the kernel .config file with the defconfig_affected mapping:
        {
            cve_id: {
                file1: CONFIG_X,
                file2: CONFIG_Y,
                ...
            }
        }
    Returns:
        {
            cve_id: [CONFIG_X, CONFIG_Z]
        }

    Only returns CVEs where at least one CONFIG_* is enabled in .config.
    """
    if not os.path.isfile(origin_config):
        print(f"ERROR: Missing .config at {origin_config}")
        return {}
    configs_to_find = {
        cfg
        for cve_map in defconfig_affected.values()
        for cfg in cve_map.values()
        if cfg
    }
    if not configs_to_find:
        return {}
    pattern = re.compile(
        r'^(' + "|".join(re.escape(cfg) for cfg in configs_to_find) + r')=(y|m|1)'
    )
    enabled = set()
    with open(origin_config, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if m:
                enabled.add(m.group(1))
    result = {}
    for cve_id, file_cfg_map in defconfig_affected.items():
        enabled_cfgs = list({cfg for cfg in file_cfg_map.values() if cfg in enabled})

        if enabled_cfgs:
            result[cve_id] = enabled_cfgs
    return result

def __debug_load_enabled_cves_from_file(path):
    """
    Load enabled CVEs from a previous run (debug mode).
    """
    if not os.path.isfile(path):
        print(f"ERROR: Debug mode requested but file not found: {path}")
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load debug file {path}: {e}")
        sys.exit(1)

def generate_kernel_filtered_cve_check(original_cve_path, enabled_cves, output_path):
    """
    Generate a new cve-check JSON file derived from original_cve_path but
    remove only the kernel CVEs that were in the original 'unfixed' set
    (kernel_get_cves_unfixed) and are NOT present in enabled_cves.
    """

    with open(original_cve_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: Invalid CVE check input (missing 'package')")
        sys.exit(1)

    unfixed_entries = kernel_get_cves_unfixed(original_cve_path)
    unfixed_ids = { e["id"] for e in unfixed_entries if e.get("id") }

    if isinstance(enabled_cves, dict):
        enabled_set = set(enabled_cves.keys())
    elif isinstance(enabled_cves, (list, set)):
        enabled_set = set(enabled_cves)
    else:
        enabled_set = set()
    removed = 0
    kept = 0

    for pkg in data.get("package", []):
        if pkg.get("name") != "linux-yocto":
            continue
        new_issues = []
        for issue in pkg.get("issue", []):
            iid = issue.get("id")
            if iid in unfixed_ids and iid not in enabled_set:
                removed += 1
                continue
            new_issues.append(issue)
            kept += 1
        pkg["issue"] = new_issues

    try:
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=4)
        print(f"Wrote filtered rootfs CVE report to: {output_path}")
        print(f"Kernel CVEs removed: {removed}, kept: {kept}")
    except Exception as e:
        print(f"ERROR: Failed writing {output_path}: {e}")
        sys.exit(1)
    return data

def main():
    args = get_parameters()

    if args.debug:
        print("DEBUG: Loading enabled_cves from previous output and skipping full processing...")
        os.makedirs(args.output_path, exist_ok=True)
        enabled_cves_path = os.path.join(args.output_path, "enabled.kernel_remaining_cves.json")
        enabled_cves = __debug_load_enabled_cves_from_file(enabled_cves_path)
        output_rootfs = enabled_cves_path.replace(".kernel_remaining_cves.json", ".rootfs.kernel_filtered.json")
        generate_kernel_filtered_cve_check(args.cve_check_input, enabled_cves, output_rootfs)
        sys.exit(0)

    unfixed = kernel_get_cves_unfixed(args.cve_check_input)

    print(f"CVEs found unpatched CVEs in cve-check file: {len(unfixed)}")

    if args.verbose:
        for entry in unfixed:
            print(f"- {entry['id']} (package: {entry['package']}, status: {entry['status']})")

    print(f"Fetching unpatched CVEs NVD details... May take a while...")

    nvd_results = {} 

    for entry in unfixed:
        cve_id = entry["id"]
        urls = nvd_get_cve(cve_id, args.nvd_api_key) 
        if args.verbose:
            print(f"{cve_id}:")
        if urls:
            nvd_results[cve_id] = urls
            if args.verbose:
                for u in urls:
                    print(f"  - {u}")
                print()
        elif args.verbose:
            print("  No URLs found.")
            print()

    print(f"Successfully retrieved NVD data for {len(nvd_results)} out of {len(unfixed)} CVEs.")
    
    git_kernel_matches = kernel_filter_git_kernel_org(nvd_results)
    
    print(f"CVEs containing git.kernel.org stable patches: {len(git_kernel_matches)}")
    
    if args.verbose:
        for cve_id, urls in git_kernel_matches.items():
            print(f"\n{cve_id}:")
            for u in urls:
                if u.startswith("https://git.kernel.org/stable/"):
                    print(f"  - {u}")
                    
    kernel_clone_git_kernel_org(GIT_KERNEL_ORG_PATH)

    modified_files_results = kernel_get_modified_files(GIT_KERNEL_ORG_PATH, git_kernel_matches)

    if args.verbose:
        for cve_id, files in modified_files_results.items():
            print(f"\n{cve_id} modified files:")
            for f in files:
                print(f"  - {f}")

    print(f"CVEs with available patched files references: {len(modified_files_results)}")

    defconfigs = kernel_find_defconfig_arguments(args.kernel_path, modified_files_results)

    if args.verbose:
        for cve_id, files_configs in defconfigs.items():
            print(f"\n{cve_id} CONFIG mappings:")
            for f, cfg in files_configs.items():
                print(f"  {f} -> {cfg}")
                
    print(f"CVEs with defconfig arguments found: {len(modified_files_results)}")
    
    enabled_cves = kernel_defconfig_comparaison(args.config_path, defconfigs)

    print(f"CVEs which affects the kernel once filtered: {len(enabled_cves)}")
    
    if args.verbose:
        for cve, cfgs in enabled_cves.items():
            print(f"  {cve}: {', '.join(cfgs)}")

    os.makedirs(args.output_path, exist_ok=True)
    enabled_cves_path = os.path.join(args.output_path, "enabled.kernel_remaining_cves.json")

    try:
        with open(enabled_cves_path, "w", encoding="utf-8") as out:
            json.dump(enabled_cves, out, indent=4)
        print(f"Wrote enabled CVEs to: {enabled_cves_path}")
    except Exception as e:
        print(f"ERROR: Failed to write output file {enabled_cves_path}: {e}")
        sys.exit(1)

    filtered_rootfs_path = os.path.join(args.output_path, "filtered.rootfs.json")
    generate_kernel_filtered_cve_check(args.cve_check_input, enabled_cves, filtered_rootfs_path)

if __name__ == "__main__":
    main()
