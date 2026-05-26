-- Run this ONCE to add Audit_Log table
-- (Add to your existing cybersecurity_irs database)

USE cybersecurity_irs;

CREATE TABLE IF NOT EXISTS Audit_Log (
    log_id     INT          AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(100) NOT NULL,
    action     VARCHAR(100) NOT NULL,
    details    TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
);
