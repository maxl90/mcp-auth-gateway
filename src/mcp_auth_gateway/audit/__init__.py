"""Structured, redacted-by-default audit logging.

One JSON record per tool invocation: who/what/when/outcome — never the
arguments. The redaction is the point: per-user attribution without the data
leaving the network. Records are written locally (stdout + file); cloud
aggregation of *signed* audit metadata is a later, separate product.
"""
