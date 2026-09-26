-- AFTERLOCK schema 0002: indexes for the worker claim query and cluster-scoped listings.

CREATE INDEX jobs_claimable_idx ON jobs (created_at) WHERE state IN ('queued', 'leased', 'running');
CREATE INDEX results_case_idx ON results (cluster_id, case_id, created_at);
