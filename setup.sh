#!/bin/bash
# Streamlit Cloud setup script
# Installs Playwright browser binaries after package installation
# Streamlit Cloud runs this automatically if named setup.sh

PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright playwright install chromium --with-deps 2>/dev/null || \
PLAYWRIGHT_BROWSERS_PATH=$HOME/.cache/ms-playwright playwright install chromium 2>/dev/null || \
echo "Playwright browser install skipped (will fall back to requests mode)"
