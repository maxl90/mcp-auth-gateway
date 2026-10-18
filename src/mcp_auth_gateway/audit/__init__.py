"""Structured, redacted-by-default audit records.

One JSON record per tool invocation: who (the agent and the human it acted for),
what tool, which upstream, when, and the outcome. Argument values are never
recorded; structural metadata about them is. Records are hash-chained and
written locally to stdout and a file.
"""
