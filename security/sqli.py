import re

SQLI_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bselect\b.+\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdelete\s+from\b",
    r"\bdrop\s+table\b",
    r"\bupdate\b.+\bset\b",
    r"\bor\s+1\s*=\s*1\b",
    r"\band\s+1\s*=\s*1\b",
    r"'\s*or\s*'1'\s*=\s*'1",
    r"information_schema",
    r"xp_cmdshell",
    r"--",
]


def detect_sqli(raw_text):

    text = raw_text.lower()

    for pattern in SQLI_PATTERNS:
      if re.search(pattern, text):
        print("MATCHED PATTERN:", pattern)
        print("TEXT:", text)
        return {
            "detected": True,
            "pattern": pattern
        }

    return {
        "detected": False,
        "pattern": None
    }