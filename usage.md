# Aggressive detection
python log_analyzer.py /var/log/auth.log -t 3 -w 5 -jr aggressive_scan.json

# Multi-source scan
python log_analyzer.py /var/log/auth.log /var/log/nginx/access.log -jr full_scan.json

# Merge over time (track repeat offenders)
python log_analyzer.py /var/log/auth.log -jr weekly.json
python log_analyzer.py /var/log/auth.log -jr weekly.json --merge

# CSV export for spreadsheets
python log_analyzer.py /var/log/auth.log -f csv -o export.csv
