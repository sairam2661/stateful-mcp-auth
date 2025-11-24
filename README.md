# Stateful MCP Authorization

Evaluation framework for stateful authorization in MCP servers.

## Overview

This project implements and evaluates stateful authorization for MCP servers, demonstrating how state tracking prevents attacks that traditional authorization systems cannot catch.

## Files

- `eval_framework.py` - Test framework with 200 test cases
- `mcp_server.py` - FastMCP server with stateful authorization
- `compare_approaches.py` - Compare different approaches 

## Quick Start
```bash
# Install dependencies
pip install fastmcp tabulate

# Run MCP server evaluation
python mcp_server.py

# Compare authorization approaches
python compare_approaches.py
```