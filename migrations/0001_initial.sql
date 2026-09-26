-- AFTERLOCK schema 0001: evidence cases, immutable analysis manifests, leased jobs, results.
-- Applied by afterlock_api.migrate. Never edit an applied migration; add a new file.
-- Every row carries cluster_id; application queries always filter on it.
-- Tokens and Secret bodies are never stored: cases hold the sanitized projection only.

CREATE TABLE cases (
    case_id       text PRIMARY KEY CHECK (case_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    cluster_id    text NOT NULL CHECK (length(cluster_id) BETWEEN 1 AND 128),
    content_hash  text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    input         jsonb NOT NULL,
    diagnostics   jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, case_id)
);

-- Immutable, content-addressed description of exactly what a job computes on.
CREATE TABLE analysis_manifests (
    manifest_id       text PRIMARY KEY,
    cluster_id        text NOT NULL,
    case_id           text NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('analysis', 'plan', 'verification')),
    input_hash        text NOT NULL CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
    semantic_profile  jsonb NOT NULL,
    engine_version    text NOT NULL,
    payload           jsonb NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, manifest_id),
    FOREIGN KEY (cluster_id, case_id) REFERENCES cases (cluster_id, case_id)
);

CREATE TABLE jobs (
    job_id            text PRIMARY KEY,
    cluster_id        text NOT NULL,
    manifest_id       text NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('analysis', 'plan', 'verification')),
    state             text NOT NULL CHECK (state IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled')),
    lease_owner       text,
    lease_expires_at  timestamptz,
    heartbeat_at      timestamptz,
    attempts          integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts      integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    cancel_requested  boolean NOT NULL DEFAULT false,
    last_error        text,
    created_by        text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, job_id),
    FOREIGN KEY (cluster_id, manifest_id) REFERENCES analysis_manifests (cluster_id, manifest_id),
    -- A lease exists exactly while the job is leased or running.
    CHECK ((state IN ('leased', 'running')) = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (attempts <= max_attempts)
);

-- Published results. UNIQUE (job_id) makes publication idempotent: a job publishes at most once.
-- Synchronous API analyses have job_id NULL.
CREATE TABLE results (
    result_id       text PRIMARY KEY,
    cluster_id      text NOT NULL,
    case_id         text NOT NULL,
    manifest_id     text NOT NULL,
    job_id          text UNIQUE,
    kind            text NOT NULL CHECK (kind IN ('analysis', 'plan', 'verification')),
    result_version  integer NOT NULL DEFAULT 1 CHECK (result_version >= 1),
    result          jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (cluster_id, manifest_id) REFERENCES analysis_manifests (cluster_id, manifest_id),
    FOREIGN KEY (cluster_id, job_id) REFERENCES jobs (cluster_id, job_id)
);

-- Evidence, manifests, and published results are immutable. Deletion is refused too, so no
-- retention job can silently remove evidence that a published result depends on.
CREATE FUNCTION afterlock_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'afterlock: % is immutable (% refused)', TG_TABLE_NAME, TG_OP;
END
$$;

CREATE TRIGGER cases_immutable BEFORE UPDATE OR DELETE ON cases
    FOR EACH ROW EXECUTE FUNCTION afterlock_reject_mutation();
CREATE TRIGGER analysis_manifests_immutable BEFORE UPDATE OR DELETE ON analysis_manifests
    FOR EACH ROW EXECUTE FUNCTION afterlock_reject_mutation();
CREATE TRIGGER results_immutable BEFORE UPDATE OR DELETE ON results
    FOR EACH ROW EXECUTE FUNCTION afterlock_reject_mutation();
