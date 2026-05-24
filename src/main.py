import re
import json

with open("input/raw-text.txt", "r") as file:
    text = file.read()

print("File loaded successfully.\n")


# security check: look for common SQL injection or XSS patterns

sql_found = re.search(r"(DROP TABLE|DELETE FROM|INSERT INTO)", text, re.IGNORECASE)
xss_found = re.search(r"<script.*?>", text, re.IGNORECASE)

if sql_found or xss_found:
    print("WARNING: Dangerous content detected! Cleaning it out.\n")

# Remove the dangerous parts to process the rest safely
text = re.sub(r"<script.*?</script>", "", text, flags=re.IGNORECASE)
text = re.sub(r"(DROP TABLE|DELETE FROM|INSERT INTO)[^\n]*", "", text, flags=re.IGNORECASE)

# Extracting data using regex patterns
# Extracting emails
all_emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

# Remove bad emails — reject if there is more than one @ or double dots (..)
emails = [e for e in all_emails if e.count("@") == 1 and ".." not in e]

# Grouping emails into ALU categories.
alu_alumni   = [e for e in emails if re.search(r"@alumni\.alueducation\.com$", e)]
alu_si       = [e for e in emails if re.search(r"@si\.alueducation\.com$", e)]
alu_official = [e for e in emails if re.search(r"@alueducation\.com$", e) and e not in alu_alumni + alu_si]
external     = [e for e in emails if e not in alu_official + alu_alumni + alu_si]

# Extracting URLs
urls = re.findall(r"https?://[^\s]+", text)

# Extracting phone numbers
# Pattern A covers US format: +1 (415) 555-0192  or  (212) 555-0134
# Pattern B covers international: +250 788 123 456
phones_a = [m.group() for m in re.finditer(r"(\+\d{1,3}\s)?(\(?\d{3}\)?[\s.-])\d{3}[\s.-]\d{4}", text)]
phones_b = [m.group() for m in re.finditer(r"\+\d{1,3}[\s.-]\d{3}[\s.-]\d{3}[\s.-]\d{3}", text)]
phones = phones_a + phones_b

# Extracting credit card numbers
raw_cards = re.findall(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", text)

cards = []
for card in raw_cards:
    digits = re.sub(r"[\s-]", "", card)  # strip spaces/dashes to get just digits

    # Security: reject if all 16 digits are the same
    if len(set(digits)) == 1:
        print(f"Rejected fake card: {card}")
        continue

    # Security: mask the number and only show last 4 digits in the output
    masked = "************" + digits[-4:]
    cards.append(masked)




# Printing results

print("----- OUTPUTS RESULTS -----\n")

print(f"EMAILS ({len(emails)} found):")
print(f"  ALU Official : {alu_official}")
print(f"  ALU Alumni   : {alu_alumni}")
print(f"  ALU SI       : {alu_si}")
print(f"  External     : {external}")

print(f"\nURLs ({len(urls)} found):")
for url in urls:
    print(f"  {url}")

print(f"\nPHONE NUMBERS ({len(phones)} found):")
for p in phones:
    print(f"  {p}")

print(f"\nCREDIT CARDS ({len(cards)} found - masked for security):")
for c in cards:
    print(f"  {c}")




# Saving results to JSON file

results = {
    "emails": {
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "external": external
    },
    "urls": urls,
    "phone_numbers": phones,
    "credit_cards": {
        "note": "Only last 4 digits shown for security",
        "numbers": cards
    }
   
}

with open(r"output/sample-output.json", "w") as f:
    json.dump(results, f, indent=4)

print("\nResults saved to output/sample-output.json")
