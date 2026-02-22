#!/bin/sh
pkill -9 -f dev_server
uv run python recoverage/dev_server.py
