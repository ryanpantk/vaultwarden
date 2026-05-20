CREATE TABLE reports (
    uuid            VARCHAR(36) NOT NULL PRIMARY KEY,
    user_uuid       VARCHAR(36),
    org_uuid        VARCHAR(36),
    exposed_count   INTEGER NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    last_updated_at TIMESTAMP NOT NULL,

    FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    FOREIGN KEY (org_uuid) REFERENCES organizations (uuid)
);
