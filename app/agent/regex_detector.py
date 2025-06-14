


import re

REGEX_PATTERNS = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'email'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
    (r'\b(?:\d[ -]*?){13,16}\b', 'credit_card'),
    (r'\b(?:\+?\d{1,4}[ -.]?)?(?:\(?\d{1,4}\)?[ -.]?)?\d{1,4}(?:[ -.]?\d{1,4}){1,5}\b', 'phone'),
    (r'\b\d{5}(?:[-\s]\d{4})?\b', 'zipcode'),
    (r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}\b', 'date'),
    (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'ipv4'),
    (r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b', 'ipv6'),
    (r'\bhttps?://[^\s]+', 'url'),
    (r"\b([A-Z][a-z]+(?:['-][A-Z][a-z]+)?)(?:\s+[A-Z][a-z]+(?:['-][A-Z][a-z]+)?)+\b", 'name'),
    
]



# Map entity types to dummy replacement strings consistent with rule_engine
DUMMY_VALUES = {
    "PHONE": "XXX-XXX-XXXX",
    "EMAIL": "user@example.com",
    "NAME": "User_",
    "ADDRESS": "1234 Main St",
    "CREDIT_CARD": "XXXX-XXXX-XXXX-XXXX",
    "SSN": "XXX-XX-XXXX",
    "ZIPCODE": "00000",
    "DATE": "01 Jan 1970",
    "IPV4": "0.0.0.0",
    "IPV6": "0000:0000:0000:0000:0000:0000:0000:0000",
    "URL": "http://example.com",
}

def detect_sensitive_data_regex_only(text: str):
    entities = []
    for pattern, entity_type in REGEX_PATTERNS:
        for match in re.finditer(pattern, text):
            replacement = DUMMY_VALUES.get(entity_type.upper(), "[MASKED]")
            length = match.end() - match.start()
            # Pad or truncate replacement to match original length
            if len(replacement) < length:
                replacement = replacement.ljust(length, " ")
            else:
                replacement = replacement[:length]

            entities.append({
                'text': match.group(),
                'start': match.start(),
                'end': match.end(),
                'entity': entity_type.upper(),
                'replacement': replacement,
                'category': 'mask'
            })
    return entities
