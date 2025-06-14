
import streamlit as st
import requests
import html

# Page setup
st.set_page_config(page_title="SniffNMask", layout="wide")

# Theme state initialization
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = False

# Top layout: title + toggle
with st.container():
    col_title, col_toggle = st.columns([9, 1])
    with col_title:
        st.title("SniffNMask")
    with col_toggle:
        dark_mode_toggle = st.toggle(
            label=":crescent_moon: Dark Mode",
            value=st.session_state.dark_mode,
            label_visibility="collapsed",
        )
        if dark_mode_toggle != st.session_state.dark_mode:
            st.session_state.dark_mode = dark_mode_toggle
            st.rerun()

# Theme variables
if st.session_state.dark_mode:
    bg_color = "#1E1E1E"
    text_color = "#F1F1F1"
    box_bg = "#2C2C2C"
    mark_color = "#FFCC70"
    border_color = "#555"
    button_bg = "#444"
    button_text = "#fff"
else:
    bg_color = "#FFFFFF"
    text_color = "#000000"
    box_bg = "#F8F9FA"
    mark_color = "#FFEEBA"
    border_color = "#ddd"
    button_bg = "#E0E0E0"
    button_text = "#000"

# Apply CSS styling
st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}
    [data-testid="stSidebar"] {{
        background-color: {box_bg} !important;
        color: {text_color} !important;
    }}
    [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] label, 
    [data-testid="stSidebar"] .css-1v3fvcr, 
    [data-testid="stSidebar"] .css-1dq8tca {{
        color: {text_color} !important;
    }}
    h1, h2, h3 {{
        color: {text_color} !important;
    }}
    textarea {{
        background-color: {box_bg} !important;
        color: {text_color} !important;
    }}
    .stDownloadButton button {{
        background-color: {button_bg} !important;
        color: {button_text} !important;
    }}
    [data-testid="stSidebar"] button[kind="primary"] {{
        color: red !important;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar widgets
st.sidebar.header("Configuration")
method = st.sidebar.selectbox("Sanitization Method", ["llm", "regex"])
uploaded_file = st.sidebar.file_uploader("📁 Upload a file (.txt, .csv, .json)", type=["txt", "csv", "json"])
sanitize_btn = st.sidebar.button("🖌️ Sanitize")

file_content = ""
if uploaded_file:
    file_content = uploaded_file.read().decode("utf-8")

st.subheader("Input Text")
original_text = st.text_area("Original text", value=file_content, height=400)

def sanitize_text_with_highlight(original, entities):
    sanitized = original
    highlights = []
    offset = 0
    for ent in sorted(entities, key=lambda e: e["start"]):
        start = ent["start"] + offset
        end = ent["end"] + offset
        replacement = ent.get("replacement") or "[MASKED]"
        sanitized = sanitized[:start] + replacement + sanitized[end:]
        highlights.append((start, start + len(replacement)))
        offset += len(replacement) - (end - start)
    return sanitized, highlights

def highlight_masked_entities(text, highlights):
    highlighted = ""
    last = 0
    for start, end in highlights:
        highlighted += html.escape(text[last:start])
        highlighted += f"<mark style='background-color:{mark_color}; border-radius:4px;'>{html.escape(text[start:end])}</mark>"
        last = end
    highlighted += html.escape(text[last:])
    return highlighted.replace("\n", "<br>")

def reconstruct_text(sanitized_text, mapping):
    reconstructed = sanitized_text
    for placeholder, original in mapping.items():
        reconstructed = reconstructed.replace(placeholder, original)
    return reconstructed

if sanitize_btn:
    if not original_text.strip():
        st.warning("Please enter some text or upload a file.")
    else:
        try:
            files = {"file": ("input.txt", original_text)}
            #res = requests.post(f"http://localhost:8000/sanitize?method={method}", files=files)
            res = requests.post(f"http://gdprsan-backend:8000/sanitize?method={method}", files=files)
            data = res.json()

            st.session_state.detected_entities = data.get("entities", [])
            st.session_state.backend_sanitized_text = data.get("sanitized", original_text)
            st.session_state.mapping = data.get("mapping", {})
            st.session_state.original_text = original_text

        except Exception as e:
            st.error("Sanitization failed. Make sure the API server is running.")
            st.exception(e)

# Show results if available in session_state
if "backend_sanitized_text" in st.session_state and "detected_entities" in st.session_state:
    sanitized_text, masked_spans = sanitize_text_with_highlight(
        st.session_state.original_text,
        st.session_state.detected_entities
    )
    highlighted_sanitized = highlight_masked_entities(sanitized_text, masked_spans)

    st.subheader("🧼 Sanitized Text")
    st.markdown(
        f"<div style='background-color:{box_bg}; padding:12px; border-radius:6px; border:1px solid {border_color}; "
        f"font-family:monospace; font-size:14px; overflow-x:auto; color:{text_color};'>{highlighted_sanitized}</div>",
        unsafe_allow_html=True,
    )

    st.subheader("Detected Entities")
    if st.session_state.detected_entities:
        for ent in st.session_state.detected_entities:
            st.markdown(f"- **{ent.get('entity', ent.get('category', 'unknown'))}**: `{ent['text']}`")
    else:
        st.info("No entities detected.")

    st.download_button(
        label="⬇️ Download Sanitized Text",
        data=sanitized_text,
        file_name="sanitized.txt",
        mime="text/plain"
    )

    if st.session_state.mapping:
        st.subheader("🔁 Reconstructed Original Text")
        recovered_text = reconstruct_text(st.session_state.backend_sanitized_text, st.session_state.mapping)
        st.text_area("Recovered Original Text", recovered_text, height=300)

        st.download_button(
            label="⬇️ Download Reconstructed Text",
            data=recovered_text,
            file_name="reconstructed.txt",
            mime="text/plain"
        )
else:
    st.info("Upload a file or enter text, then click 'Sanitize'.")
