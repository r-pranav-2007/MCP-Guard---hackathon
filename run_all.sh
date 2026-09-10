#!/bin/bash
python servers/calculator_server.py &
python servers/docs_server.py &
python proxy/main.py
