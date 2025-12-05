#!/usr/bin/env python3
import argparse
import os
import sys

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


def display_cve_check_input(path):
    print("CVE Check Input:", path)


def main():
    args = get_parameters()
    display_cve_check_input(args.cve_check_input)
    print("Kernel Path:", args.kernel_path)
    print("CVE Check Output:", args.cve_check_output)


if __name__ == "__main__":
    main()
