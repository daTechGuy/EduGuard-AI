#!/usr/bin/env python3
"""
GrizzDog-AI: Turnkey Canvas LMS Batch Grader & Integrity Verifier
==================================================================
Scans a batch of student markdown lab reports (.md), validates cryptographic
HMAC signatures, verifies rule provenance, scores Parts 2 & 3 (55 pts auto),
tallies completed reflection brief questions, and generates a Canvas LMS
gradebook CSV ready for direct import.

Affiliation: Butler Community College Cyber Defense Faculty Project (Andover Campus)
Adapted from foundational cybersecurity architecture by SixFiveMil (https://github.com/SixFiveMil/Securing-AI).

Usage:
    # Basic usage on a folder of submissions:
    python lab/scripts/batch_grade.py submissions/

    # With instructor HMAC secret verification:
    REPORT_SECRET="my_instructor_secret" python lab/scripts/batch_grade.py submissions/ --csv canvas_grades.csv

    # Specifying individual files:
    python lab/scripts/batch_grade.py report1.md report2.md --secret "my_instructor_secret"
"""

import argparse
import csv
import glob
import os
import re
import sys
from pathlib import Path

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(__file__))

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
except ImportError:
    # Graceful fallback if colorama is not installed
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

from report_signing import get_secret, verify_report


def extract_regex(pattern, text, default=""):
    m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else default


def parse_lab_report(text, filepath, secret=""):
    """Parse a student lab report markdown file and extract all grading fields."""
    # 1. Student metadata
    student_raw = extract_regex(r"\*\*Student\*\*:\s*([^\n\r]+)", text, "Unknown Student")
    student_name = student_raw
    student_email = ""
    if "(" in student_raw and ")" in student_raw:
        parts = student_raw.split("(", 1)
        student_name = parts[0].strip()
        student_email = parts[1].replace(")", "").replace("`", "").strip()

    course_section = extract_regex(r"\*\*Course/Section\*\*:\s*([^\n\r]+)", text, "N/A")
    instructor = extract_regex(r"\*\*Instructor\*\*:\s*([^\n\r]+)", text, "N/A")
    timestamp = extract_regex(r"\*\*Submission Timestamp\*\*:\s*`?([^\n\r`]+)`?", text, "N/A")
    fingerprint = extract_regex(r"\*\*Rules Fingerprint[^\*]*\*\*:\s*`?([^\n\r`]+)`?", text, "N/A")

    # 2. Scorecard metrics
    composite_str = extract_regex(r"\*\*Composite Defense Score\*\*:\s*\*\*?([0-9\.]+)", text, "0.0")
    attack_rate_str = extract_regex(r"\*\*Adversarial Attack Catch Rate\*\*:\s*\*\*?([0-9\.]+)", text, "0.0")
    benign_rate_str = extract_regex(r"\*\*Benign Usability Pass Rate\*\*:\s*\*\*?([0-9\.]+)", text, "0.0")

    # 3. Rubric item auto-scores
    part2_str = extract_regex(r"\|\s*\*\*2\.\s*Gateway Rule Implementation\*\*\s*\|\s*35 pts\s*\|\s*([0-9\.]+)\s*pts", text, "")
    part3_str = extract_regex(r"\|\s*\*\*3\.\s*Usability & False Positive Control\*\*\s*\|\s*20 pts\s*\|\s*([0-9\.]+)\s*pts", text, "")
    auto_total_str = extract_regex(r"\|\s*\*\*AUTO-SCORED SUBTOTAL\*\*\s*\|\s*\*\*55 pts\*\*\s*\|\s*\*\*?([0-9\.]+)", text, "")

    try:
        part2_pts = float(part2_str) if part2_str else 0.0
    except ValueError:
        part2_pts = 0.0

    try:
        part3_pts = float(part3_str) if part3_str else 0.0
    except ValueError:
        part3_pts = 0.0

    try:
        auto_total_pts = float(auto_total_str) if auto_total_str else (part2_pts + part3_pts)
    except ValueError:
        auto_total_pts = part2_pts + part3_pts

    # 4. Reflection brief completion
    reflections_completed = 0
    ref_matches = re.findall(r"###\s*\d+\)\s*[^\n\r]+\n\s*>\s*([^\n\r]+)", text)
    for quote_line in ref_matches:
        q = quote_line.strip().lower()
        if q and not q.startswith("_(no response)_") and not q.startswith("<em>(no response)</em>"):
            reflections_completed += 1

    # 5. Provenance check
    rule_provenance = extract_regex(r"\*\*Rule Provenance\*\*:\s*([^\n\r]+)", text, "")
    is_preset = "matches shipped" in rule_provenance.lower() or "0 auto-points" in rule_provenance.lower()

    # 6. HMAC Signature verification
    hmac_status = "UNKNOWN"
    hmac_detail = ""
    if "UNSIGNED - practice copy" in text:
        hmac_status = "UNSIGNED"
        hmac_detail = "Practice copy (exported without secret)"
    elif secret:
        ok, msg = verify_report(text, secret)
        if ok:
            hmac_status = "VALID"
            hmac_detail = "Cryptographically sealed & untampered"
        else:
            hmac_status = "INVALID"
            hmac_detail = f"Tampered / mismatched ({msg})"
    else:
        sig_match = re.search(r"\*\*Report Signature \(HMAC-SHA256\)\*\*:\s*`([a-f0-9]{64})`", text)
        if sig_match:
            hmac_status = "SIGNED"
            hmac_detail = "HMAC present (set --secret to verify)"
        else:
            hmac_status = "UNSIGNED"
            hmac_detail = "No signature line found"

    return {
        "file": os.path.basename(filepath),
        "filepath": filepath,
        "student_name": student_name,
        "student_email": student_email,
        "course_section": course_section,
        "instructor": instructor,
        "timestamp": timestamp,
        "fingerprint": fingerprint,
        "composite_score": float(composite_str),
        "attack_catch_rate": float(attack_rate_str),
        "benign_pass_rate": float(benign_rate_str),
        "part2_pts": part2_pts,
        "part3_pts": part3_pts,
        "auto_total_pts": auto_total_pts,
        "reflections_completed": reflections_completed,
        "rule_provenance": rule_provenance,
        "is_preset": is_preset,
        "hmac_status": hmac_status,
        "hmac_detail": hmac_detail,
    }


def find_report_files(targets):
    """Find all markdown report files from file or directory arguments."""
    files = []
    if not targets:
        # Default: check ./submissions or current dir
        if os.path.isdir("submissions"):
            files.extend(glob.glob("submissions/*.md"))
        else:
            files.extend(glob.glob("*_Report_*.md"))
            files.extend(glob.glob("GrizzDog_Lab_Report_*.md"))
            files.extend(glob.glob("EduGuard_Lab_Report_*.md"))
        return sorted(list(set(files)))

    for target in targets:
        if os.path.isdir(target):
            files.extend(glob.glob(os.path.join(target, "**", "*.md"), recursive=True))
        elif os.path.isfile(target):
            files.append(target)
        else:
            matches = glob.glob(target)
            if matches:
                files.extend(matches)
            else:
                print(f"{Fore.YELLOW}[WARN] Target not found: {target}")

    return sorted(list(set(files)))


def write_canvas_csv(records, output_csv):
    """Export standard Canvas gradebook CSV."""
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Standard Canvas Gradebook Headers
        writer.writerow([
            "Student",
            "ID",
            "SIS User ID",
            "SIS Login ID",
            "Section",
            "AI Defense Lab Auto-Grade (55 max)",
            "Part 2 Gateway Rules (35 max)",
            "Part 3 Usability Control (20 max)",
            "Reflections Completed (5 max)",
            "HMAC Integrity Status",
            "Rule Provenance",
            "Fingerprint",
            "Report File",
        ])

        for r in records:
            # Format student name as 'Last, First' if possible
            name = r["student_name"]
            parts = name.split(" ")
            if len(parts) >= 2:
                formatted_name = f"{parts[-1]}, {' '.join(parts[:-1])}"
            else:
                formatted_name = name

            login_id = r["student_email"].split("@")[0] if "@" in r["student_email"] else ""

            writer.writerow([
                formatted_name,
                login_id,
                "",  # SIS User ID
                login_id,
                r["course_section"],
                f"{r['auto_total_pts']:.1f}",
                f"{r['part2_pts']:.1f}",
                f"{r['part3_pts']:.1f}",
                f"{r['reflections_completed']}/5",
                r["hmac_status"],
                "PRESET (0 auto pts)" if r["is_preset"] else "Custom Rules",
                r["fingerprint"],
                r["file"],
            ])


def main():
    parser = argparse.ArgumentParser(
        description="GrizzDog-AI: Turnkey Canvas LMS Batch Grader & Integrity Verifier"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Path(s) to student .md files or folder containing submissions (default: submissions/)",
    )
    parser.add_argument(
        "--secret",
        default="",
        help="HMAC secret used by the instructor server (or set via REPORT_SECRET env var)",
    )
    parser.add_argument(
        "--csv",
        default="canvas_grades.csv",
        help="Output CSV file path for Canvas gradebook import (default: canvas_grades.csv)",
    )
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="Fail with exit code 1 if any submission is unsigned or invalid",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed test case and reflection breakdowns",
    )
    args = parser.parse_args()

    secret = args.secret.strip() or get_secret()
    files = find_report_files(args.paths)

    if not files:
        print(f"{Fore.RED}[ERROR] No student markdown reports (.md) found.")
        print(f"Place student reports in {Fore.CYAN}submissions/{Fore.RESET} or specify files directly.")
        print("Usage: python lab/scripts/batch_grade.py submissions/ [--secret <SECRET>]")
        return 2

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 86}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}🐾 GrizzDog-AI // Butler Cyber Defense Lab — Canvas Batch Grader & HMAC Verifier")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}{'=' * 86}")
    print(f"Submissions Found: {Fore.CYAN}{len(files)}{Fore.RESET} files")
    if secret:
        print(f"HMAC Verification: {Fore.GREEN}ACTIVE{Fore.RESET} (Key: {secret[:4]}...{secret[-4:] if len(secret) > 8 else ''})")
    else:
        print(f"HMAC Verification: {Fore.YELLOW}STANDBY{Fore.RESET} (Provide --secret or set REPORT_SECRET to verify signatures)")
    print(f"Output CSV:        {Fore.CYAN}{args.csv}{Fore.RESET}\n")

    records = []
    has_tampered = False

    header_fmt = f"{'Student Name':<22} {'Section':<11} {'Part 2':<8} {'Part 3':<8} {'Auto/55':<9} {'Reflect':<8} {'HMAC Status'}"
    print(f"{Style.BRIGHT}{header_fmt}")
    print("-" * 86)

    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            print(f"{Fore.RED}[READ ERROR] {fpath}: {e}")
            continue

        r = parse_lab_report(content, fpath, secret=secret)
        records.append(r)

        # Status badge color
        if r["hmac_status"] == "VALID":
            status_badge = f"{Fore.GREEN}[VALID ✓]{Fore.RESET}"
        elif r["hmac_status"] == "INVALID":
            status_badge = f"{Fore.RED}[TAMPERED 🚨]{Fore.RESET}"
            has_tampered = True
        elif r["hmac_status"] == "SIGNED":
            status_badge = f"{Fore.CYAN}[SIGNED 🔒]{Fore.RESET}"
        else:
            status_badge = f"{Fore.YELLOW}[UNSIGNED ⚠️]{Fore.RESET}"

        # Preset penalty display
        if r["is_preset"]:
            auto_str = f"{Fore.RED}0.0 (Preset){Fore.RESET}"
        else:
            auto_str = f"{r['auto_total_pts']:.1f} pts"

        row = (
            f"{r['student_name'][:21]:<22} "
            f"{r['course_section'][:10]:<11} "
            f"{r['part2_pts']:>4.1f}/35 "
            f"{r['part3_pts']:>4.1f}/20 "
            f"{auto_str:<9} "
            f"{r['reflections_completed']}/5      "
            f"{status_badge}"
        )
        print(row)

        if args.verbose:
            print(f"   {Fore.WHITE}File:{Fore.RESET} {r['file']} | {Fore.WHITE}Catch Rate:{Fore.RESET} {r['attack_catch_rate']}% | {Fore.WHITE}Usability:{Fore.RESET} {r['benign_pass_rate']}%")
            print(f"   {Fore.WHITE}Provenance:{Fore.RESET} {r['rule_provenance']} | {Fore.WHITE}HMAC Detail:{Fore.RESET} {r['hmac_detail']}\n")

    print("-" * 86)

    # Summary Statistics
    total_count = len(records)
    avg_score = sum(r["auto_total_pts"] for r in records) / total_count if total_count else 0
    valid_count = sum(1 for r in records if r["hmac_status"] == "VALID")
    tampered_count = sum(1 for r in records if r["hmac_status"] == "INVALID")
    unsigned_count = sum(1 for r in records if r["hmac_status"] in ("UNSIGNED", "SIGNED"))

    print(f"\n{Style.BRIGHT}Batch Grading Summary:")
    print(f"  &bull; Total Evaluated:       {total_count}")
    print(f"  &bull; Class Average (Auto): {avg_score:.1f} / 55.0 pts ({(avg_score/55.0)*100:.1f}%)")
    if secret:
        print(f"  &bull; HMAC Valid Submissions:{Fore.GREEN} {valid_count}{Fore.RESET}")
        if tampered_count > 0:
            print(f"  &bull; Tampered Submissions:  {Fore.RED} {tampered_count} (FLAGGED FOR REVIEW){Fore.RESET}")
    print(f"  &bull; Unsigned Submissions:  {unsigned_count}")

    # Write Canvas CSV
    write_canvas_csv(records, args.csv)
    print(f"\n{Fore.GREEN}[SUCCESS]{Fore.RESET} Canvas Gradebook CSV generated: {Style.BRIGHT}{args.csv}{Style.RESET_ALL}")
    print(f"Import directly into Butler Canvas LMS via: {Fore.CYAN}Grades -> Actions -> Import CSV{Fore.RESET}\n")

    if args.require_signed and (has_tampered or unsigned_count > 0):
        return 1
    if has_tampered:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
