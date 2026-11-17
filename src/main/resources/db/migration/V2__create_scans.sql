CREATE TABLE scan (
    id             BIGSERIAL    PRIMARY KEY,
    target_url     VARCHAR(500) NOT NULL,
    status         VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    authorized_by  VARCHAR(50)  NOT NULL,
    endpoints_seen INT          NOT NULL DEFAULT 0,
    error_message  VARCHAR(1000),
    started_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ
);

CREATE TABLE finding (
    id              BIGSERIAL    PRIMARY KEY,
    scan_id         BIGINT       NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
    owasp_category  VARCHAR(60)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    title           VARCHAR(200) NOT NULL,
    url             VARCHAR(500) NOT NULL,
    method          VARCHAR(10)  NOT NULL,
    evidence        VARCHAR(2000),
    remediation     VARCHAR(1000)
);

CREATE INDEX idx_finding_scan_id ON finding (scan_id);
