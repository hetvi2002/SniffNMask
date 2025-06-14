

from fastapi import FastAPI, File, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Literal
from app.agent.llm_detector import detect_sensitive_data
from app.agent.regex_detector import detect_sensitive_data_regex_only
from app.agent.rule_engine import mask_text
import logging

logger = logging.getLogger(__name__)
app = FastAPI()

@app.post("/sanitize")
async def sanitize_file(
    file: UploadFile = File(...),
    method: Literal["llm", "regex"] = Query("llm")
):
    content_bytes = await file.read()
    content = content_bytes.decode("utf-8", errors="ignore")

    logger.info(f"Sanitization requested with method={method}, file size={len(content_bytes)} bytes")

    # Step 1: Detect entities
    if method == "regex":
        entities = detect_sensitive_data_regex_only(content)
    else:
        entities = detect_sensitive_data(content)

    logger.info(f"Detected {len(entities)} entities")

    # Step 2: Mask text and retrieve mapping
    sanitized, updated_entities, mapping = mask_text(content, entities)

    return {
        "original": content,
        "sanitized": sanitized,
        "entities": updated_entities,
        "mapping": mapping  # <== includes dummy -> original for reversal
    }
