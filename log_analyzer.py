#!/usr/bin/env python3
"""
Log Analyzer - Detects suspicious activities from system and server logs.
Features: brute force detection, error spike analysis, anomaly scoring, reporting.
"""

import re
import os
import sys
import json
import gzip
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

CONFIG = {
    "brute_force_threshold": 5,       # Failed attempts in window to flag
    "brute_force_window_minutes": 10, # Time window for brute force detection
    "error_spike_threshold": 50,      # Errors in window to flag as spike
    "error_spike_window_minutes": 5,  # Time window for error spike
    "suspicious_ip_blocklist": [],    # Known bad IPs (optional)
    "output_format": "plain",         # plain, json, or csv
    "report_file": None,              # None = stdout, or path to file
}

# ─── Log Patterns ─────────────────────────────────────────────────────────────

# Auth log patterns (Linux /var/log/auth.log, /var/log/secure)
AUTH_FAIL_PATTERN = re.compile(
    r'(Failed password|authentication failure|FAILED LOGIN|Invalid user)'
    r'.*?(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE
)

AUTH_SUCCESS_PATTERN = re.compile(
    r'(Accepted password|Accepted publickey|session opened)'
    r'.*?(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE
)

# Web server log patterns (Apache/Nginx Common/Combined format)
WEB_STATUS_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[([^\]]+)\]\s+"[A-Z]+\s+(\S+)\s+\S+"\s+(\d{3})'
)

# Generic timestamp patterns (flexible)
TIMESTAMP_PATTERN = re.compile(
    r'(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2})'
)

# SQL injection detection patterns
SQLI_PATTERNS = [
    re.compile(r"(\%27|'|--|drop\s+table|union\s+select|or\s+1=1)", re.IGNORECASE),
    re.compile(r"(<script|<iframe|alert\(|onerror=|onload=)", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\)|/etc/passwd|/proc/self', re.IGNORECASE)

# ─── Core Analyzer ────────────────────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self, config=None):
        self.config = {**CONFIG, **(config or {})}
        self.failed_auths = defaultdict(list)   # IP -> list of timestamps
        self.success_auths = defaultdict(list)  # IP -> list of timestamps
        self.http_errors = defaultdict(list)    # IP -> list of (timestamp, status, path)
        self.sql_attempts = defaultdict(list)   # IP -> list of paths
        self.path_traversals = defaultdict(list)
        self.anomaly_scores = defaultdict(float)
        self.total_lines = 0
        self.parse_errors = 0

    def _parse_timestamp(self, raw):
        """Try to extract a datetime from various log timestamp formats."""
        match = TIMESTAMP_PATTERN.search(raw)
        if match:
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]:
                try:
                    return datetime.strptime(match.group(1), fmt)
                except ValueError:
                    pass
        # Web log format: 10/Oct/2000:13:55:36
        match = re.search(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', raw)
        if match:
            try:
                return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
        return datetime.now()  # fallback

    def _within_window(self, timestamps, now, window_minutes):
        cutoff = now - timedelta(minutes=window_minutes)
        return [t for t in timestamps if t > cutoff]

    def analyze_auth_line(self, line, line_num):
        """Analyze a single auth log line."""
        # Failed auths
        fail_match = AUTH_FAIL_PATTERN.search(line)
        if fail_match:
            ip = fail_match.group(2)
            ts = self._parse_timestamp(line)
            self.failed_auths[ip].append(ts)

        # Successful auths
        success_match = AUTH_SUCCESS_PATTERN.search(line)
        if success_match:
            ip = success_match.group(2)
            ts = self._parse_timestamp(line)
            self.success_auths[ip].append(ts)

    def analyze_web_line(self, line, line_num):
        """Analyze a single web server log line."""
        match = WEB_STATUS_PATTERN.search(line)
        if not match:
            return

        ip = match.group(1)
        raw_ts = match.group(2)
        path = match.group(3)
        status = int(match.group(4))

        ts = self._parse_timestamp(raw_ts)

        # Track HTTP errors (4xx, 5xx)
        if 400 <= status < 600:
            self.http_errors[ip].append((ts, status, path))

        # SQL injection attempts
        for pattern in SQLI_PATTERNS:
            if pattern.search(line):
                self.sql_attempts[ip].append(path)
                break

        # Path traversal attempts
        if PATH_TRAVERSAL_PATTERN.search(line):
            self.path_traversals[ip].append(path)

    def analyze_line(self, line, line_num):
        """Route a log line to the appropriate analyzer."""
        self.total_lines += 1
        if not line.strip():
            return

        try:
            self.analyze_auth_line(line, line_num)
            self.analyze_web_line(line, line_num)
        except Exception:
            self.parse_errors += 1

    def score_ip(self, ip):
        """Calculate an anomaly score for an IP address."""
        score = 0.0
        now = datetime.now()

        # Brute force score
        recent_fails = self._within_window(
            self.failed_auths.get(ip, []), now,
            self.config["brute_force_window_minutes"]
        )
        if len(recent_fails) >= self.config["brute_force_threshold"]:
            score += min(len(recent_fails) * 2.0, 40.0)

        # Error rate score
        recent_errors = self._within_window(
            [t for t, _, _ in self.http_errors.get(ip, [])], now,
            self.config["error_spike_window_minutes"]
        )
        if len(recent_errors) >= self.config["error_spike_threshold"]:
            score += min(len(recent_errors) * 1.5, 30.0)

        # SQLi score
        if self.sql_attempts.get(ip):
            score += min(len(self.sql_attempts[ip]) * 5.0, 20.0)

        # Path traversal score
        if self.path_traversals.get(ip):
            score += min(len(self.path_traversals[ip]) * 5.0, 20.0)

        return score

    def run(self, log_paths):
        """Main entry: read all log files and run analysis."""
        # Ensure logs directory exists
        log_dir = Path(log_paths[0]).resolve().parent if len(log_paths) == 1 else Path(log_paths[0]).resolve().parent

        if not log_paths:
            print("[!] No log files specified.")
            print(f"    Usage: {sys.argv[0]} /var/log/auth.log")
            print(f"    Or:    {sys.argv[0]} /var/log/nginx/access.log")
            sys.exit(1)

        line_num = 0
        for log_path in log_paths:
            path = Path(log_path)
            if not path.exists():
                print(f"[!] Skipping: {log_path} (not found)")
                continue

            open_func = gzip.open if path.suffix == '.gz' else open
            mode = 'rt' if path.suffix == '.gz' else 'r'

            try:
                with open_func(path, mode, encoding='utf-8', errors='replace') as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        line_num += 1
                        self.analyze_line(line, line_num)
            except PermissionError:
                print(f"[!] Permission denied: {log_path} (try sudo)")
            except Exception as e:
                print(f"[!] Error reading {log_path}: {e}")

        # Score all IPs
        all_ips = set()
        for ip_list in [self.failed_auths, self.success_auths, self.http_errors,
                        self.sql_attempts, self.path_traversals]:
            if isinstance(ip_list, defaultdict):
                all_ips.update(ip_list.keys())

        for ip in all_ips:
            self.anomaly_scores[ip] = self.score_ip(ip)

        return self.generate_report()

    # ─── Reporting ────────────────────────────────────────────────────────────

    def generate_report(self):
        """Generate and output a report of all findings."""
        report_data = {
            "scan_time": datetime.now().isoformat(),
            "total_lines_processed": self.total_lines,
            "parse_errors": self.parse_errors,
            "findings": []
        }

        suspicious_ips = sorted(
            [(ip, score) for ip, score in self.anomaly_scores.items() if score > 0],
            key=lambda x: x[1], reverse=True
        )

        for ip, score in suspicious_ips:
            finding = {
                "ip": ip,
                "anomaly_score": round(score, 1),
                "severity": "CRITICAL" if score >= 50 else "HIGH" if score >= 30 else "MEDIUM" if score >= 15 else "LOW",
                "failed_auths": len(self.failed_auths.get(ip, [])),
                "successful_auths": len(self.success_auths.get(ip, [])),
                "http_errors": len(self.http_errors.get(ip, [])),
                "sqli_attempts": len(self.sql_attempts.get(ip, [])),
                "path_traversals": len(self.path_traversals.get(ip, [])),
            }
            report_data["findings"].append(finding)

        fmt = self.config["output_format"]

        if fmt == "json":
            output = json.dumps(report_data, indent=2)
        elif fmt == "csv":
            lines = ["ip,anomaly_score,severity,failed_auths,successful_auths,http_errors,sqli_attempts,path_traversals"]
            for f in report_data["findings"]:
                lines.append(f"{f['ip']},{f['anomaly_score']},{f['severity']},{f['failed_auths']},{f['successful_auths']},{f['http_errors']},{f['sqli_attempts']},{f['path_traversals']}")
            output = "\n".join(lines)
        else:  # plain
            lines = [
                "=" * 70,
                "  LOG ANALYZER REPORT",
                f"  Scan time: {report_data['scan_time']}",
                f"  Lines processed: {self.total_lines}",
                f"  Parse errors: {self.parse_errors}",
                "=" * 70,
                ""
            ]
            if not report_data["findings"]:
                lines.append("[+] No suspicious activity detected.")
            else:
                lines.append(f"{'IP':<18} {'Score':<8} {'Severity':<10} {'Fail':<6} {'Success':<8} {'Errors':<7} {'SQLi':<5} {'Traversal':<10}")
                lines.append("-" * 70)
                for f in report_data["findings"]:
                    lines.append(
                        f"{f['ip']:<18} {f['anomaly_score']:<8} {f['severity']:<10} "
                        f"{f['failed_auths']:<6} {f['successful_auths']:<8} "
                        f"{f['http_errors']:<7} {f['sqli_attempts']:<5} {f['path_traversals']:<10}"
                    )
            output = "\n".join(lines)

        if self.config["report_file"]:
            with open(self.config["report_file"], "w") as f:
                f.write(output)
            print(f"[+] Report written to {self.config['report_file']}")
        else:
            print(output)

        return report_data


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Log Analyzer — Detect suspicious activity in system/web logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze auth logs for brute force attempts
  python log_analyzer.py /var/log/auth.log

  # Analyze web server logs
  python log_analyzer.py /var/log/nginx/access.log

  # Multiple files with JSON output
  python log_analyzer.py /var/log/auth.log /var/log/syslog -f json -o report.json

  # Custom thresholds for aggressive detection
  python log_analyzer.py /var/log/auth.log -t 3 -w 5
        """
    )

    parser.add_argument("logs", nargs="+", help="Log file(s) to analyze")
    parser.add_argument("-t", "--threshold", type=int, default=CONFIG["brute_force_threshold"],
                        help=f"Failed attempts threshold (default: {CONFIG['brute_force_threshold']})")
    parser.add_argument("-w", "--window", type=int, default=CONFIG["brute_force_window_minutes"],
                        help=f"Time window in minutes (default: {CONFIG['brute_force_window_minutes']})")
    parser.add_argument("-f", "--format", choices=["plain", "json", "csv"], default="plain",
                        help="Output format")
    parser.add_argument("-o", "--output", help="Write report to file instead of stdout")

    args = parser.parse_args()

    config = {
        "brute_force_threshold": args.threshold,
        "brute_force_window_minutes": args.window,
        "output_format": args.format,
        "report_file": args.output,
    }

    analyzer = LogAnalyzer(config)
    analyzer.run(args.logs)
