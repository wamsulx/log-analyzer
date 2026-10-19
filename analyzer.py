import re
import base64
import html
from collections import defaultdict

log_file = "sample.log"
template_file = "template.html"
html_report_file = "security_report.html"
threshold = 3

def parse_logs(file_path):
    events = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                events.append((line_num, line.strip()))
    except FileNotFoundError:
        print("Error: Log file not found.")
    return events

def generate_html_report(failed_logins, powershell_alerts, user_creations, admin_additions):
    try:
        with open(template_file, "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        print("Error: Template file not found.")
        return

    # 1. Brute force section
    brute_found = any(count >= threshold for count in failed_logins.values())
    if brute_found:
        brute_html = '<ul>'
        for ip, count in failed_logins.items():
            if count >= threshold:
                brute_html += f"<li><b>Suspicious IP:</b> {html.escape(ip)} — <b>{count}</b> failed login attempts</li>"
        brute_html += '</ul>'
    else:
        brute_html = '<p class="no-data">No brute-force activity detected.</p>'

    # 2. PowerShell section
    if powershell_alerts:
        ps_html = '<ul>'
        for line_num, raw, decoded in powershell_alerts:
            ps_html += f"<li><b>Line {line_num}:</b> Encoded command detected<br>Raw B64: <code>{html.escape(raw)}</code><br>Decoded Payload: <code>{html.escape(decoded)}</code></li>"
        ps_html += '</ul>'
    else:
        ps_html = '<p class="no-data">No suspicious PowerShell commands found.</p>'

    # 3. Account changes section
    if user_creations or admin_additions:
        acc_html = '<ul>'
        for line_num, line in user_creations:
            acc_html += f"<li><b>Line {line_num}:</b> Account creation detected — <code>{html.escape(line)}</code></li>"
        for line_num, line in admin_additions:
            acc_html += f"<li><b>Line {line_num}:</b> Group membership change detected — <code>{html.escape(line)}</code></li>"
        acc_html += '</ul>'
    else:
        acc_html = '<p class="no-data">No suspicious account modifications found.</p>'

    # Injecting generated HTML into template placeholders
    report_content = template.replace("{{ brute_force_section }}", brute_html)
    report_content = report_content.replace("{{ powershell_section }}", ps_html)
    report_content = report_content.replace("{{ account_changes_section }}", acc_html)

    with open(html_report_file, "w", encoding="utf-8") as f:
        f.write(report_content)

def analyze():
    failed_logins = defaultdict(int)
    powershell_alerts = []
    user_creations = []
    admin_additions = []

    print("Starting analysis...")
    events = parse_logs(log_file)
    if not events:
        return

    for line_num, line in events:
        if "EventID=4625" in line:
            ip_match = re.search(r"IP=(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                failed_logins[ip_match.group(1)] += 1

        if "PowerShell" in line:
            ps_match = re.search(r"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]+)", line, re.IGNORECASE)
            if ps_match:
                raw_b64 = ps_match.group(1)
                try:
                    decoded_bytes = base64.b64decode(raw_b64)
                    decoded_cmd = decoded_bytes.decode('utf-16-le', errors='ignore')
                except Exception:
                    decoded_cmd = raw_b64
                powershell_alerts.append((line_num, raw_b64, decoded_cmd))

        if "EventID=4720" in line:
            user_creations.append((line_num, line))

        if "EventID=4732" in line:
            admin_additions.append((line_num, line))

    generate_html_report(failed_logins, powershell_alerts, user_creations, admin_additions)
    print("Analysis finished. HTML report generated: security_report.html")

if __name__ == "__main__":
    analyze()