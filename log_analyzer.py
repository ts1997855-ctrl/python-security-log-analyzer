REPORT_FILE = "output/security_report.txt"
from collections import Counter

LOG_FILE = "sample_logs/security.log"
REPORT_FILE = "output/security_report.txt"
ALERT_THRESHOLD = 3

failed_login_ips = []
successful_logins = 0
file_access_events = 0

with open(LOG_FILE, "r", encoding="utf-8") as log_file:
    for line in log_file:
        line = line.strip()

        if "LOGIN_FAILED" in line:
            parts = line.split()

            for part in parts:
                if part.startswith("ip="):
                    ip_address = part.replace("ip=", "")
                    failed_login_ips.append(ip_address)

        elif "LOGIN_SUCCESS" in line:
            successful_logins += 1

        elif "FILE_ACCESS" in line:
            file_access_events += 1


failed_ip_counts = Counter(failed_login_ips)

print("=" * 55)
print("SECURITY LOG ANALYZER")
print("=" * 55)

print(f"Successful logins: {successful_logins}")
print(f"Failed logins: {len(failed_login_ips)}")
print(f"File access events: {file_access_events}")

print("\nFAILED LOGIN ATTEMPTS BY IP")
print("-" * 55)

for ip_address, count in failed_ip_counts.items():
    print(f"{ip_address}: {count} failed attempt(s)")

print("\nSECURITY ALERTS")
print("-" * 55)
print("Analysis complete.")

report_lines = []

report_lines.append("SECURITY LOG ANALYSIS REPORT")
report_lines.append("=" * 55)
report_lines.append(f"Successful logins: {successful_logins}")
report_lines.append(f"Failed logins: {len(failed_login_ips)}")
report_lines.append(f"File access events: {file_access_events}")
report_lines.append("")

report_lines.append("FAILED LOGIN ATTEMPTS BY IP")
report_lines.append("-" * 55)

for ip_address, count in failed_ip_counts.items():
    report_lines.append(
        f"{ip_address}: {count} failed attempt(s)"
    )

report_lines.append("")
report_lines.append("SECURITY ALERTS")
report_lines.append("-" * 55)

for ip_address, count in failed_ip_counts.items():

    if count >= 5:
        severity = "HIGH"
    elif count >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if count >= ALERT_THRESHOLD:
        report_lines.append(
            f"[{severity} ALERT] {ip_address} generated "
            f"{count} failed login attempts."
        )

with open(REPORT_FILE, "w", encoding="utf-8") as report_file:
    report_file.write("\n".join(report_lines))

print(f"Report saved to: {REPORT_FILE}")

