CREATE TABLE users (
                       id         BIGSERIAL    PRIMARY KEY,
                       username   VARCHAR(50)  NOT NULL UNIQUE,
                       password   VARCHAR(100) NOT NULL,
                       role       VARCHAR(20)  NOT NULL DEFAULT 'USER',
                       enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
                       created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);