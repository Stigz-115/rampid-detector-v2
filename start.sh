#!/bin/bash
# Start script for RampID Detector Streamlit app
# Usage: bash start.sh

export PATH="$HOME/.local/bin:$PATH"

APP_PORT="${APP_PORT:-3000}"

cd "$(dirname "$0")"

uv run streamlit run app.py --server.port "$APP_PORT" --server.headless true
