"""
Lab 11 — Configuration & API Key Setup
"""
import os


def setup_api_key():
    """Load Google API key from environment when available.

    The lab can run deterministic guardrail tests without a key, while ADK/Gemini
    demos use GOOGLE_API_KEY when the user has already configured it.
    """
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    if "GOOGLE_API_KEY" in os.environ and os.environ["GOOGLE_API_KEY"].strip():
        print("GOOGLE_API_KEY detected.")
        return True
    print("GOOGLE_API_KEY not set; API demos will use deterministic fallbacks where available.")
    return False


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
