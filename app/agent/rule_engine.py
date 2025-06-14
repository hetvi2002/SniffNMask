

import logging

DUMMY_VALUES = {
    "PHONE": "XXX-XXX-XXXX",
    "EMAIL": "user@example.com",
    "NAME": "User_____",
    "ADDRESS": "1234 Main St",
    "CREDIT_CARD": "XXXX-XXXX-XXXX-XXXX",
    "SSN": "XXX-XX-XXXX",
    "ZIPCODE": "00000",
    "DATE": "01 Jan 1970",
    "IPV4": "0.0.0.0",
    "IPV6": "0000:0000:0000:0000:0000:0000:0000:0000",
    "URL": "http://example.com",
    "REDACTED": "[REDACTED]",
    "MASKED": "[MASKED]",
}

ENTITY_NORMALIZATION = {
    "phone": "PHONE",
    "email": "EMAIL",
    "name": "NAME",
    "address": "ADDRESS",
    "credit_card": "CREDIT_CARD",
    "ssn": "SSN",
    "zipcode": "ZIPCODE",
    "date": "DATE",
    "ipv4": "IPV4",
    "ipv6": "IPV6",
    "url": "URL",
    "masked": "MASKED",
}

logger = logging.getLogger("uvicorn.error")

def normalize_entity(entity_label: str) -> str:
    return ENTITY_NORMALIZATION.get(entity_label.lower(), entity_label.upper())



def mask_text(text: str, entities: list) -> tuple[str, list, dict]:
    """
    Replace detected entity spans in the text with consistent dummy values.
    Returns:
        - masked_text: the sanitized version of the text
        - updated_entities: entities with dummy replacements
        - mapping: dummy -> original for reversibility
    """

    entities_sorted = sorted(entities, key=lambda e: e["start"], reverse=True)
    logger.debug(f"Masking entities: {entities_sorted}")

    category_counters = {}  # for generating unique dummies
    dummy_mapping = {}      # dummy -> original
    updated_entities = []

    for ent in entities_sorted:
        start, end = ent["start"], ent["end"]
        original = ent["text"]
        entity_label = ent.get("entity") or ent.get("type") or ""
        norm_label = normalize_entity(entity_label)

        # Generate unique dummy value
        count = category_counters.get(norm_label, 1)
        dummy = f"{norm_label.lower()}_{count}"
        category_counters[norm_label] = count + 1

        dummy_mapping[dummy] = original

        # Ensure dummy length matches original length for inline masking
        if len(dummy) < (end - start):
            replacement = dummy.ljust(end - start, " ")
        else:
            replacement = dummy[:end - start]

        # Update text
        text = text[:start] + replacement + text[end:]
       

        # Save updated entity for debugging
        updated_entities.append({
            "start": start,
            "end": start + len(replacement),
            "text": original,
            "replacement": replacement,
            "entity": norm_label,
        })

    return text, updated_entities, dummy_mapping
