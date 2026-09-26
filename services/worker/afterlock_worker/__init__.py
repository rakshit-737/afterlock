"""AFTERLOCK job worker: leased execution of analysis, plan, and verification jobs.

The worker reads only immutable manifests from storage, runs the pure engine on them, and
publishes results through ``Storage.complete``, which re-checks the lease in the publishing
transaction. See ``afterlock_worker.runner``.
"""
