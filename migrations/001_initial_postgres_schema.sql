-- ====================================================================
-- Enterprise Governance Engine: Distributed Financial Ledger Schema
-- Target: PostgreSQL 14+ (ACID Row-Locking & Transactional Outbox)
-- ====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Budget Scope / Partition Accounts (Locking Anchor)
CREATE TABLE IF NOT EXISTS budget_accounts (
    budget_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    budget_subject_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    budget_limit NUMERIC(24, 8) NOT NULL CHECK (budget_limit >= 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    lock_version BIGINT NOT NULL DEFAULT 0 CHECK (lock_version >= 0),
    next_outbox_seq BIGINT NOT NULL DEFAULT 1 CHECK (next_outbox_seq > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_budget_scope UNIQUE (tenant_id, budget_subject_id, currency),
    CONSTRAINT uq_budget_account_scope UNIQUE (budget_account_id, tenant_id, currency)
);

-- 2. Logical Gateway Operations & Strict Idempotency Registry
CREATE TABLE IF NOT EXISTS gateway_operations (
    operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    provider_id TEXT NOT NULL CHECK (btrim(provider_id) <> ''),
    budget_account_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    payload_hash BYTEA NOT NULL CHECK (octet_length(payload_hash) = 32),
    amount NUMERIC(24, 8) NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    recipient_id TEXT NOT NULL CHECK (btrim(recipient_id) <> ''),
    status TEXT NOT NULL CHECK (status IN (
        'PENDING', 'RESERVED', 'DISPATCH_INTENT', 'IN_FLIGHT',
        'COMMITTED', 'ABORTED', 'OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED'
    )),
    policy_version TEXT NOT NULL,
    provider_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    CONSTRAINT uq_operation_idempotency UNIQUE (tenant_id, provider_id, idempotency_key),
    CONSTRAINT uq_operation_binding UNIQUE (operation_id, budget_account_id, tenant_id, currency, amount),
    CONSTRAINT fk_operation_budget_account FOREIGN KEY (budget_account_id, tenant_id, currency)
        REFERENCES budget_accounts (budget_account_id, tenant_id, currency)
);

-- 3. Dedicated Financial Budget Reservations
CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL UNIQUE,
    budget_account_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount NUMERIC(24, 8) NOT NULL CHECK (amount > 0),
    status TEXT NOT NULL CHECK (status IN (
        'RESERVED', 'DISPATCH_INTENT', 'IN_FLIGHT', 'COMMITTED',
        'RECONCILIATION_REQUIRED', 'EXPIRED_UNRESOLVED', 'RELEASED', 'ABORTED'
    )),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    dispatch_intent_at TIMESTAMPTZ,
    in_flight_at TIMESTAMPTZ,
    committed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    CONSTRAINT fk_reservation_operation FOREIGN KEY (operation_id, budget_account_id, tenant_id, currency, amount)
        REFERENCES gateway_operations (operation_id, budget_account_id, tenant_id, currency, amount),
    CONSTRAINT fk_reservation_budget_account FOREIGN KEY (budget_account_id, tenant_id, currency)
        REFERENCES budget_accounts (budget_account_id, tenant_id, currency),
    CONSTRAINT ck_reservation_expiry CHECK (expires_at IS NULL OR expires_at >= reserved_at),
    CONSTRAINT ck_committed_timestamp CHECK (status <> 'COMMITTED' OR committed_at IS NOT NULL),
    CONSTRAINT ck_released_timestamp CHECK (status <> 'RELEASED' OR released_at IS NOT NULL),
    CONSTRAINT ck_dispatch_timestamp CHECK (status <> 'DISPATCH_INTENT' OR dispatch_intent_at IS NOT NULL),
    CONSTRAINT ck_in_flight_timestamp CHECK (status <> 'IN_FLIGHT' OR in_flight_at IS NOT NULL)
);

-- 4. Transactional Outbox for Fault-Tolerant Asynchronous Dispatch
CREATE TABLE IF NOT EXISTS transactional_outbox (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL REFERENCES gateway_operations(operation_id),
    aggregate_id UUID NOT NULL REFERENCES budget_accounts(budget_account_id),
    aggregate_seq BIGINT NOT NULL CHECK (aggregate_seq > 0),
    event_type TEXT NOT NULL,
    event_version SMALLINT NOT NULL DEFAULT 1 CHECK (event_version > 0),
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'LEASED', 'DISPATCHED', 'RETRY_WAIT', 'DEAD_LETTER')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    processed_at TIMESTAMPTZ,
    CONSTRAINT uq_outbox_aggregate_sequence UNIQUE (aggregate_id, aggregate_seq),
    CONSTRAINT uq_outbox_operation_event UNIQUE (operation_id, event_type, event_version),
    CONSTRAINT ck_outbox_lease CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR
        (status <> 'LEASED' AND lease_owner IS NULL AND lease_until IS NULL)
    )
);

-- Strategic Partial Indexes for High-Throughput Hot Paths
CREATE INDEX IF NOT EXISTS idx_operations_recovery
ON gateway_operations (status, updated_at, operation_id)
WHERE status IN ('PENDING', 'RESERVED', 'DISPATCH_INTENT', 'IN_FLIGHT', 'OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED');

CREATE INDEX IF NOT EXISTS idx_reservations_active_holds
ON budget_reservations (budget_account_id, status)
INCLUDE (amount)
WHERE status IN ('RESERVED', 'DISPATCH_INTENT', 'IN_FLIGHT', 'RECONCILIATION_REQUIRED', 'EXPIRED_UNRESOLVED');

CREATE INDEX IF NOT EXISTS idx_reservations_committed_window
ON budget_reservations (budget_account_id, committed_at)
INCLUDE (amount)
WHERE status = 'COMMITTED';

CREATE INDEX IF NOT EXISTS idx_outbox_ready
ON transactional_outbox (available_at, created_at, event_id)
WHERE status IN ('PENDING', 'RETRY_WAIT');

CREATE INDEX IF NOT EXISTS idx_outbox_expired_lease
ON transactional_outbox (lease_until, available_at, event_id)
WHERE status = 'LEASED';

CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_reference
ON gateway_operations (tenant_id, provider_id, provider_reference)
WHERE provider_reference IS NOT NULL;
