# check_email.py
# Reads one email file (.eml) and checks it for common phishing signs.
# Usage: python3 check_email.py path/to/email.eml

import sys
import re
import email
from email import policy
from email.utils import parseaddr


# --- Step 1: Get the email file name from the command line ---
# sys.argv is the list of words typed after "python3".
# If the user didn't give a file name, show how to use the script and stop.
if len(sys.argv) != 2:
    print("Usage: python3 check_email.py path/to/email.eml")
    sys.exit(1)

file_path = sys.argv[1]


# --- Step 2: Open the file and let Python's email library read it ---
# "rb" means read the file as raw bytes, which is how emails are stored.
with open(file_path, "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)


# --- Step 3: Pull out the three sender-related addresses ---
# From        = who the email claims to be from (what you see in your inbox)
# Reply-To    = where your reply will actually go
# Return-Path = where bounced/failed emails go (set by the sending server)
# parseaddr() strips the display name, e.g. '"PayPal" <a@b.com>' -> 'a@b.com'
print("=== Sender Addresses ===")
domains = {}
for header in ["From", "Reply-To", "Return-Path"]:
    address = parseaddr(msg.get(header, ""))[1].lower()
    if address:
        print(f"{header:12}: {address}")
        # Keep only the part after "@" so we can compare domains
        domains[header] = address.split("@")[-1]
    else:
        print(f"{header:12}: (missing)")


# --- Step 4: Warn if the domains don't all match ---
# A real company usually sends, receives replies, and handles bounces
# on the same domain. Different domains are a common phishing sign.
# set() removes duplicates, so more than one item means a mismatch.
if len(set(domains.values())) > 1:
    print("\nWARNING: Sender domains do not match!")
    for header, domain in domains.items():
        print(f"  {header:12} -> {domain}")
else:
    print("\nOK: Sender domains match.")


# --- Step 5: Check SPF, DKIM and DMARC results ---
# The receiving mail server records these checks in the
# "Authentication-Results" header, e.g. "spf=pass dkim=fail dmarc=fail".
#   SPF   = was the sending server allowed to send for this domain?
#   DKIM  = does the email's digital signature check out?
#   DMARC = the domain owner's policy that ties SPF/DKIM to the From address
print("\n=== Authentication Checks ===")
auth_results = " ".join(msg.get_all("Authentication-Results", []))

for check in ["spf", "dkim", "dmarc"]:
    # Look for text like "spf=pass" and grab the word after "="
    match = re.search(rf"\b{check}=(\w+)", auth_results, re.IGNORECASE)
    result = match.group(1).lower() if match else "missing"

    # Anything other than "pass" is suspicious
    flag = "" if result == "pass" else "  <-- WARNING"
    print(f"{check.upper():6}: {result}{flag}")
