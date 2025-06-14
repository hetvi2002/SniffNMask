
import httpx
import re
import json
import yaml
import os
import logging

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "llama3.2:latest")

rules_path = os.path.join(os.path.dirname(__file__), "../../sanitization_rules.yaml")
with open(rules_path, "r") as f:
    rules_data = yaml.safe_load(f)
rules = rules_data.get("rules", [])

instruction_lines = []
for rule in rules:
    for line in rule.get("instructions", []):
        instruction_lines.append(f"- {line.strip()}")
INSTRUCTION_PREFIX = "\n".join(instruction_lines)



PROMPT_TEMPLATE = '''
You are a data sanitizer AI.

Follow these rules to sanitize input text:
{rules}

Your job is to identify **all personal or sensitive entities** in the given text and return each entity as a JSON object.

Each JSON object MUST include:
- "type" – one of: name, email, phone, ip, url, date
- "text" – the EXACT value from the input (verbatim)
- "category" – masked
- "replacement" – the sanitized version of "text"

Important Notes:
- Names include both single and full names (e.g., "Rebecca", "Rebecca Adams").
- Always mask all phone numbers, including those with dashes, spaces, or parentheses.
- Phone numbers can be in formats such as: 415-867-5309, (415) 867-5309, +1 415 867 5309.
- Do NOT mask common short words such as greetings ("Hi", "Hello") or filler words.
- Return entities in order of appearance.
- Do not miss masking any detected entities.

✅ Examples:

Input:
Customer: Hi, this is Rebecca Adams. I called earlier but got disconnected.
Customer: My email is rebecca.adams1985@gmail.com.
Customer: My phone number is 415-867-5309.

Output:
[
  {{ "type": "name", "text": "Rebecca Adams", "category": "mask", "replacement": "User" }},
  {{ "type": "email", "text": "rebecca.adams1985@gmail.com", "category": "mask", "replacement": "user@example.com" }},
  {{ "type": "phone", "text": "415-867-5309", "category": "mask", "replacement": "XXX-XXX-XXXX" }}
]

Now use the same format.

Text:
{text}

Return ONLY a JSON array. Do NOT include commentary or explanation.
'''



logger = logging.getLogger("uvicorn.error")

def detect_sensitive_data(text: str):
    prompt = PROMPT_TEMPLATE.format(text=text, rules=INSTRUCTION_PREFIX)
    try:
        response = httpx.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        content = response.json().get("response", "")
        
        # Attempt to parse JSON from response robustly
        try:
            # Sometimes LLM may output extra text, try to isolate JSON array
            json_start = content.find('[')
            json_end = content.rfind(']') + 1
            json_text = content[json_start:json_end]
            raw_entities = json.loads(json_text)
        except Exception:
            logger.warning("Failed to parse JSON from LLM response, returning empty entity list.")
            return []

        enriched = []
        for e in raw_entities:
            if all(k in e for k in ("type", "text", "category", "replacement")):
                try:
                    start = text.index(e["text"])
                    enriched.append({
                        "entity": e["type"].upper(),
                        "text": e["text"],
                        "category": e["category"],
                        "replacement": e["replacement"],
                        "start": start,
                        "end": start + len(e["text"])
                    })
                except ValueError:
                    
                    continue
        return enriched
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return []
