-- AFTERLOCK schema 0003: case ids are unique per cluster, not globally.
-- Before this, creating a case whose id already existed in another cluster returned 409,
-- which told the caller that the id exists somewhere they cannot see.
-- UNIQUE (cluster_id, case_id) from 0001 remains and becomes the primary key;
-- analysis_manifests already references cases (cluster_id, case_id).

ALTER TABLE cases DROP CONSTRAINT cases_pkey;
ALTER TABLE cases ADD PRIMARY KEY (cluster_id, case_id);
