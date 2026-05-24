# ALU Data Extraction & Secure Validation Program

This is a program or tool that helps us with secure data extraction using regex(regular expressions), extracting specific types of data from raw text, and it validates input to ensure it is well-formed and does not contain unsafe or malicious content.

## Project Tree

alu-regex-data-extraction_chuloezi/
├── input/
│   └── raw-text.txt             
├── src/
│   └── main.py                   
├── output/
│   └── sample-output.json        
└── README.md                     

### Regex patterns

These patterns look for specific data in the raw text:

Email Pattern: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

This finds standard usernames, an @ symbol, domain name, and standard extensions like .com or .rw.

Credit Card Pattern: Matches 15 or 16 digit payment card structures.

\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b (Standard 16-digits)

\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b (Amex 15-digits)

Phone Pattern: \+?\d{1,4}[-\s]?\(?\d{2,4}\)?[-\s]?\d{3}[-\s]?\d{3,4}

URL Pattern: https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*

#### Defensive Security Features

Before extracting anything, the script runs a direct check:

If a line contains dangerous terms like <script> or SQL queries like UNION SELECT, then we immediately flag it and ignore the rest of that line. This helps in keeping the program completely safe from malicious inputs

#### Credit Card Masking

The python script hides all digits of a credit caard except the last 4 digits

##### ALU Domain Specific Classifications

The script uses Python's built-in .endswith() string method to group emails according to ALU groups.

###### How to Run the Program

To run the program, open the terminal or command prompt inside the project folder

And run the program using:

python3 src/main.py  or  python src/main.py

Then, you can open output/sample-output.json to see the results