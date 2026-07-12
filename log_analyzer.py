#!/usr/bin/env python3
"""
Log Analyzer — SOC Analyst Edition
Detects suspicious activities from system and server logs.
"""

import re
import os
import sys
import json
import gzip
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import ipaddress

# ─── Configuration ────────────────────────────────────────────────────────────

CONFIG = {
    "brute_force_threshold": 5,
    "brute_force_window_minutes": 10,
    "error_spike_threshold": 50,
    "error_spike_window_minutes": 5,
    "suspicious_ip_blocklist": [],
    "output_format": "plain",
    "report_file": None,
    "json_report": "log_analysis_report.json",
    "merge_existing": False,
    "tool_name": "HackerAI-LogAnalyzer",
    "analyst": "SOC-Analyst",
}

# ─── Log Patterns ─────────────────────────────────────────────────────────────

AUTH_FAIL_PATTERN = re.compile(
    r'(Failed password|authentication failure|FAILED LOGIN|Invalid user)'
    r'.*?(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE
)

AUTH_SUCCESS_PATTERN = re.compile(
    r'(Accepted password|Accepted publickey|session opened)'
    r'.*?(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE
)

WEB_STATUS_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[([^\]]+)\]\s+"[A-Z]+\s+(\S+)\s+\S+"\s+(\d{3})'
)

TIMESTAMP_PATTERN = re.compile(
    r'(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2})'
)

SQLI_PATTERNS = [
    ("SQL-Injection", re.compile(r"(?:'|--|%27|%22|union\s+select|select\s+.*\s+from|"
                                 r"or\s+1=1|or\s+'1'='1|and\s+1=1|"
                                 r"exec\s+xp_|exec\s+sp_|waitfor\s+delay|"
                                 r"information_schema|load_file\(|into\s+outfile)", re.IGNORECASE)),
    ("XSS", re.compile(r"(?:<script|javascript:|onerror=|onload=|onclick=|"
                       r"onmouseover=|onfocus=|alert\(|confirm\(|prompt\(|"
                       r"<img\s+src|%3Cscript|%3Cimg)", re.IGNORECASE)),
]

PATH_TRAVERSAL_PATTERN = re.compile(
    r'(\.\./|\.\.\\)|/etc/passwd|/etc/shadow|/proc/self|/proc/1/cmdline|'
    r'/sys/|/var/log/|/boot/|\.env|\.git/config|wp-config\.php', re.IGNORECASE
)

PORT_SCAN_PATTERN = re.compile(r'(scan|nmap|masscan|zmap|UNION|SELECT.*FROM)', re.IGNORECASE)

SEVERITY_THRESHOLDS = [
    (50, "CRITICAL"),
    (30, "HIGH"),
    (15, "MEDIUM"),
    (5,  "LOW"),
    (0,  "INFO"),
]

# ─── Core Analyzer ────────────────────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self, config=None):
        self.config = {**CONFIG, **(config or {})}
        self.failed_auths = defaultdict(list)
        self.success_auths = defaultdict(list)
        self.http_errors = defaultdict(list)
        self.sqli_attempts = defaultdict(lambda: defaultdict(list))
        self.path_traversals = defaultdict(list)
        self.xss_attempts = defaultdict(list)
        self.anomaly_scores = defaultdict(float)
        self.ip_threats = defaultdict(set)
        self.total_lines = 0
        self.parse_errors = 0
        self.log_sources_used = []

    def _parse_timestamp(self, raw):
        match = TIMESTAMP_PATTERN.search(raw)
        if match:
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]:
                try:
                    return datetime.strptime(match.group(1), fmt)
                except ValueError:
                    pass
        match = re.search(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', raw)
        if match:
            try:
                return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})', raw)
        if match:
            try:
                return datetime.fromisoformat(match.group(1))
            except (ValueError, AttributeError):
                pass
        return datetime.now()

    def _within_window(self, timestamps, now, window_minutes):
        if not timestamps:
            return []
        cutoff = now - timedelta(minutes=window_minutes)
        return [t for t in timestamps if t > cutoff]

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def analyze_auth_line(self, line, line_num):
        fail_match = AUTH_FAIL_PATTERN.search(line)
        if fail_match:
            ip = fail_match.group(2)
            ts = self._parse_timestamp(line)
            self.failed_auths[ip].append(ts)
            self.ip_threats[ip].add("Brute-Force / Failed Login")

        success_match = AUTH_SUCCESS_PATTERN.search(line)
        if success_match:
            ip = success_match.group(2)
            ts = self._parse_timestamp(line)
            self.success_auths[ip].append(ts)

        if re.search(r'root|admin|administrator|test|user|guest', line, re.IGNORECASE):
            fail_match2 = AUTH_FAIL_PATTERN.search(line)
            if fail_match2:
                ip = fail_match2.group(2)
                self.ip_threats[ip].add("Credential-Stuffing / Targeted Username")

    def analyze_web_line(self, line, line_num):
        match = WEB_STATUS_PATTERN.search(line)
        if not match:
            return

        ip = match.group(1)
        raw_ts = match.group(2)
        path = match.group(3)
        status = int(match.group(4))
        ts = self._parse_timestamp(raw_ts)

        if 400 <= status < 600:
            self.http_errors[ip].append((ts, status, path))

        for threat_type, pattern in SQLI_PATTERNS:
            if pattern.search(line):
                if threat_type == "XSS":
                    self.xss_attempts[ip].append(path)
                self.sqli_attempts[ip][threat_type].append(path)
                self.ip_threats[ip].add(threat_type)

        if PATH_TRAVERSAL_PATTERN.search(line):
            self.path_traversals[ip].append(path)
            self.ip_threats[ip].add("Path-Traversal")

        if PORT_SCAN_PATTERN.search(line) and status in (200, 403, 404):
            self.ip_threats[ip].add("Reconnaissance / Scanning")

    def analyze_line(self, line, line_num):
        self.total_lines += 1
        if not line.strip():
            return
        try:
            self.analyze_auth_line(line, line_num)
            self.analyze_web_line(line, line_num)
        except Exception:
            self.parse_errors += 1

    def score_ip(self, ip):
        score = 0.0
        now = datetime.now()

        recent_fails = self._within_window(
            self.failed_auths.get(ip, []), now,
            self.config["brute_force_window_minutes"]
        )
        if len(recent_fails) >= self.config["brute_force_threshold"]:
            score += min(len(recent_fails) * 2.0, 40.0)

        recent_errors = self._within_window(
            [t for t, _, _ in self.http_errors.get(ip, [])], now,
            self.config["error_spike_window_minutes"]
        )
        if len(recent_errors) >= self.config["error_spike_threshold"]:
            score += min(len(recent_errors) * 1.5, 30.0)

        for ttype, paths in self.sqli_attempts.get(ip, {}).items():
            score += min(len(paths) * 5.0, 20.0)

        if self.xss_attempts.get(ip):
            score += min(len(self.xss_attempts[ip]) * 4.0, 16.0)

        if self.path_traversals.get(ip):
            score += min(len(self.path_traversals[ip]) * 5.0, 20.0)

        if ip in self.config.get("suspicious_ip_blocklist", []):
            score += 25.0

        return score

    def _get_severity(self, score):
        for threshold, label in SEVERITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "INFO"

    def run(self, log_paths):
        if not log_paths:
            print("[!] No log files specified.")
            sys.exit(1)

        line_num = 0
        for log_path in log_paths:
            path = Path(log_path)
            if not path.exists():
                print(f"[!] Skipping: {log_path} (not found)")
                continue

            self.log_sources_used.append(str(path.absolute()))
            open_func = gzip.open if path.suffix == '.gz' else open
            mode = 'rt' if path.suffix == '.gz' else 'r'

            try:
                with open_func(path, mode, encoding='utf-8', errors='replace') as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        line_num += 1
                        self.analyze_line(line, line_num)
                print(f"[✓] Processed: {path} ({line_num} lines)")
            except PermissionError:
                print(f"[!] Permission denied: {log_path} (try sudo)")
            except Exception as e:
                print(f"[!] Error reading {log_path}: {e}")

        all_ips = set()
        for container in [self.failed_auths, self.success_auths, self.http_errors,
                          self.sqli_attempts, self.path_traversals, self.xss_attempts]:
            all_ips.update(container.keys())

        for ip in all_ips:
            self.anomaly_scores[ip] = self.score_ip(ip)

        report = self.generate_report()
        self._save_json_report(report)
        return report

    def generate_report(self):
        now = datetime.now()
        report = {
            "report_metadata": {
                "tool": self.config["tool_name"],
                "version": "2.0",
                "generated_at": now.isoformat(),
                "analyst": self.config["analyst"],
            },
            "scan_summary": {
                "total_logs_processed": len(self.log_sources_used),
                "total_lines_processed": self.total_lines,
                "parse_errors": self.parse_errors,
                "total_suspicious_ips": 0,
                "sources": self.log_sources_used,
            },
            "findings": [],
            "statistics": {
                "total_failed_auths": sum(len(v) for v in self.failed_auths.values()),
                "total_successful_auths": sum(len(v) for v in self.success_auths.values()),
                "total_http_errors": sum(len(v) for v in self.http_errors.values()),
                "total_sqli_attempts": sum(
                    sum(len(p) for p in v.values()) for v in self.sqli_attempts.values()
                ),
                "total_xss_attempts": sum(len(v) for v in self.xss_attempts.values()),
                "total_path_traversals": sum(len(v) for v in self.path_traversals.values()),
                "distinct_ips_total": len(set(
                    list(self.failed_auths.keys()) +
                    list(self.success_auths.keys()) +
                    list(self.http_errors.keys()) +
                    list(self.sqli_attempts.keys()) +
                    list(self.path_traversals.keys()) +
                    list(self.xss_attempts.keys())
                )),
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            },
            "recommendations": [],
            "top_attackers": [],
        }

        suspicious_ips = sorted(
            [(ip, score) for ip, score in self.anomaly_scores.items() if score > 0],
            key=lambda x: x[1], reverse=True
        )

        for ip, score in suspicious_ips:
            severity = self._get_severity(score)
            report["statistics"]["severity_breakdown"][severity] += 1
            threats_detected = sorted(self.ip_threats.get(ip, []))

            finding = {
                "ip": ip,
                "is_private": self._is_private_ip(ip),
                "anomaly_score": round(score, 1),
                "severity": severity,
                "failed_auths": len(self.failed_auths.get(ip, [])),
                "successful_auths": len(self.success_auths.get(ip, [])),
                "http_errors": len(self.http_errors.get(ip, [])),
                "sqli_attempts": {
                    t: len(p) for t, p in self.sqli_attempts.get(ip, {}).items()
                },
                "xss_attempts": len(self.xss_attempts.get(ip, [])),
                "path_traversals": len(self.path_traversals.get(ip, [])),
                "detected_threats": threats_detected,
                "threat_count": len(threats_detected),
            }
            report["findings"].append(finding)

        report["scan_summary"]["total_suspicious_ips"] = len(report["findings"])

        report["top_attackers"] = [
            {"ip": f["ip"], "score": f["anomaly_score"], "severity": f["severity"],
             "threats": f["detected_threats"]}
            for f in report["findings"][:10]
        ]

        recs = []
        if report["statistics"]["total_failed_auths"] > 0:
            recs.append("Implement account lockout policy after 5 failed attempts.")
        if any(f["severity"] in ("CRITICAL", "HIGH") for f in report["findings"]):
            recs.append("Block identified attacking IPs at the firewall.")
        if report["statistics"]["total_sqli_attempts"] > 0:
            recs.append("Use prepared statements/parameterized queries for all database interactions.")
            recs.append("Deploy a WAF (ModSecurity / Cloudflare) with SQLi rulesets.")
        if report["statistics"]["total_xss_attempts"] > 0:
            recs.append("Implement Content-Security-Policy (CSP) headers and output encoding.")
        if report["statistics"]["total_path_traversals"] > 0:
            recs.append("Validate and sanitize file path inputs; disable directory listing.")
        if report["findings"]:
            recs.append("Correlate IPs with threat intelligence feeds (AlienVault OTX, VirusTotal).")
        recs.append("Enable auditd logging and centralize logs with a SIEM (Wazuh / ELK / Splunk).")
        report["recommendations"] = recs

        return report

    def _save_json_report(self, report):
        json_path = self.config.get("json_report")
        if not json_path:
            return

        path = Path(json_path)
        merge = self.config.get("merge_existing", False)

        if merge and path.exists():
            try:
                with open(path, "r") as f:
                    existing = json.load(f)
                existing_ips = {f["ip"] for f in existing.get("findings", [])}
                for finding in report["findings"]:
                    if finding["ip"] not in existing_ips:
                        existing["findings"].append(finding)
                existing["scan_summary"]["total_logs_processed"] += report["scan_summary"]["total_logs_processed"]
                existing["scan_summary"]["total_lines_processed"] += report["scan_summary"]["total_lines_processed"]
                existing["scan_summary"]["total_suspicious_ips"] = len(existing["findings"])
                existing["report_metadata"]["generated_at"] = datetime.now().isoformat()
                existing["recommendations"] = report["recommendations"]
                existing["top_attackers"] = report["top_attackers"]
                report = existing
                print(f"[+] Merged with existing report: {json_path}")
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!] Could not merge ({e}), overwriting.")

        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[✓] JSON report saved: {json_path} ({len(report['findings'])} findings)")

    def print_plain_report(self, report):
        lines = [
            "=" * 75,
            "  LOG ANALYZER — SOC REPORT",
            f"  Generated: {report['report_metadata']['generated_at']}",
            f"  Tool: {report['report_metadata']['tool']} v{report['report_metadata']['version']}",
            "=" * 75,
            "",
            "  SCAN SUMMARY",
            f"    Logs processed       : {report['scan_summary']['total_logs_processed']}",
            f"    Total lines processed : {report['scan_summary']['total_lines_processed']}",
            f"    Parse errors          : {report['scan_summary']['parse_errors']}",
            f"    Suspicious IPs found  : {report['scan_summary']['total_suspicious_ips']}",
            "",
            "  STATISTICS",
            f"    Failed auths       : {report['statistics']['total_failed_auths']}",
            f"    Successful auths   : {report['statistics']['total_successful_auths']}",
            f"    HTTP errors (4xx/5xx): {report['statistics']['total_http_errors']}",
            f"    SQLi attempts      : {report['statistics']['total_sqli_attempts']}",
            f"    XSS attempts       : {report['statistics']['total_xss_attempts']}",
            f"    Path traversals    : {report['statistics']['total_path_traversals']}",
            f"    Distinct IPs       : {report['statistics']['distinct_ips_total']}",
            "",
            "  SEVERITY BREAKDOWN",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"    {sev:<10}: {report['statistics']['severity_breakdown'].get(sev, 0)}")
        lines.append("")

        if not report["findings"]:
            lines.append("  [OK] No suspicious activity detected.")
        else:
            lines.append(f"  {'IP':<18} {'Score':<7} {'Severity':<10} {'Fails':<7} "
                         f"{'Errors':<7} {'SQLi':<5} {'XSS':<4} {'PathTrav':<8} {'Threats'}")
            lines.append("-" * 80)
            for f in report["findings"]:
                threats = ", ".join(f["detected_threats"][:3])
                if len(f["detected_threats"]) > 3:
                    threats += f" +{len(f['detected_threats'])-3} more"
                lines.append(
                    f"{f['ip']:<18} {f['anomaly_score']:<7} {f['severity']:<10} "
                    f"{f['failed_auths']:<7} {f['http_errors']:<7} "
                    f"{sum(f['sqli_attempts'].values()):<5} {f['xss_attempts']:<4} "
                    f"{f['path_traversals']:<8} {threats}"
                )

        lines.append("")
        lines.append("  RECOMMENDATIONS")
        for i, rec in enumerate(report["recommendations"], 1):
            lines.append(f"    {i}. {rec}")

        lines.append("")
        lines.append(f"  Full JSON report: {self.config.get('json_report', 'N/A')}")
        lines.append("=" * 75)

        out = "\n".join(lines)
        if self.config.get("report_file") and not self.config.get("json_report"):
            with open(self.config["report_file"], "w") as f:
                f.write(out)
            print(f"[+] Report written to {self.config['report_file']}")
        else:
            print(out)


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Log Analyzer — SOC Analyst Edition"
    )

    parser.add_argument("logs", nargs="+", help="Log file(s) to analyze")
    parser.add_argument("-t", "--threshold", type=int, default=CONFIG["brute_force_threshold"],
                        help=f"Failed attempts threshold (default: {CONFIG['brute_force_threshold']})")
    parser.add_argument("-w", "--window", type=int, default=CONFIG["brute_force_window_minutes"],
                        help=f"Time window in minutes (default: {CONFIG['brute_force_window_minutes']})")
    parser.add_argument("-f", "--format", choices=["plain", "json", "csv"], default="plain",
                        help="Output format")
    parser.add_argument("-o", "--output", help="Write plain/csv report to file")
    parser.add_argument("-jr", "--json-report", default=CONFIG["json_report"],
                        help=f"Path for JSON report (default: {CONFIG['json_report']})")
    parser.add_argument("--merge", action="store_true",
                        help="Merge findings with existing JSON report")
    parser.add_argument("--analyst", default="SOC-Analyst",
                        help="Analyst name for report metadata")

    args = parser.parse_args()

    config = {
        "brute_force_threshold": args.threshold,
        "brute_force_window_minutes": args.window,
        "output_format": args.format,
        "report_file": args.output,
        "json_report": args.json_report,
        "merge_existing": args.merge,
        "analyst": args.analyst,
    }

    analyzer = LogAnalyzer(config)
    report = analyzer.run(args.logs)

    if args.format != "json":
        analyzer.print_plain_report(report)
