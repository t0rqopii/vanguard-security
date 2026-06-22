"""
Sample vulnerable project to demonstrate Vanguard detection.
"""

# This file contains intentional security issues for testing purposes
import os


# Homograph attack: Cyrillic 'а' (U+0430) looks like Latin 'a'
# import rеquests  # Uncomment to test homograph detection


def fetch_data() -> str:
    """Simulate data fetching with environment variable."""
    api_key = os.environ.get("API_KEY")
    return api_key or "default"
