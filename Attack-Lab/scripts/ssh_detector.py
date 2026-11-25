import re
from collections import Counter

LOG_FILE = "ssh-lab.log"
THRESHOLD = 3

failed_attempts = Counter()

with open(LOG_FILE, "r") as file:
    for line in file:
        if "Failed password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1

print("\n===== SSH ATTACK DETECTION REPORT =====")

if not failed_attempts:
    print("No failed SSH login attempts detected.")

for ip, count in failed_attempts.items():
    print(f"\nSource IP: {ip}")
    print(f"Failed attempts: {count}")

    if count >= THRESHOLD:
        print("ALERT: Suspicious SSH activity detected!")
    else:
        print("Status: Normal activity")
