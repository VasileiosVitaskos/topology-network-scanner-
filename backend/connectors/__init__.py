"""
connectors — Data source adapters for the topological engine.

All connectors implement BaseConnector and return LogEntry objects.
The engine is source-agnostic: SSH, file, or mock all look the same.
"""