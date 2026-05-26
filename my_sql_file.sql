-- ============================================================
--  CYBERSECURITY INCIDENT RESPONSE SYSTEM — FULL SCHEMA
--  Run this file once in MySQL Workbench to set everything up
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybersecurity_irs
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cybersecurity_irs;

-- ── DROP ORDER (children first) ──────────────────────────────
DROP TABLE IF EXISTS Alerts;
DROP TABLE IF EXISTS Incidents;
DROP TABLE IF EXISTS Response_Teams;
DROP TABLE IF EXISTS Attack_Types;
DROP TABLE IF EXISTS Systems;
DROP VIEW  IF EXISTS vw_threat_dashboard;
DROP PROCEDURE IF EXISTS sp_response_time_report;

-- ── 1. SYSTEMS ───────────────────────────────────────────────
CREATE TABLE Systems (
    system_id   INT           AUTO_INCREMENT PRIMARY KEY,
    system_name VARCHAR(100)  NOT NULL,
    ip_address  VARCHAR(45),
    os_type     VARCHAR(50),
    location    VARCHAR(100),
    created_at  DATETIME      DEFAULT CURRENT_TIMESTAMP
);

-- ── 2. ATTACK TYPES ──────────────────────────────────────────
CREATE TABLE Attack_Types (
    attack_type_id INT          AUTO_INCREMENT PRIMARY KEY,
    attack_name    VARCHAR(100) NOT NULL,
    severity_level ENUM('Low','Medium','High','Critical') NOT NULL,
    description    TEXT
);

-- ── 3. RESPONSE TEAMS ────────────────────────────────────────
CREATE TABLE Response_Teams (
    team_id   INT          AUTO_INCREMENT PRIMARY KEY,
    team_name VARCHAR(100) NOT NULL,
    lead_name VARCHAR(100),
    contact   VARCHAR(100)
);

-- ── 4. INCIDENTS ─────────────────────────────────────────────
CREATE TABLE Incidents (
    incident_id    INT  AUTO_INCREMENT PRIMARY KEY,
    system_id      INT  NOT NULL,
    attack_type_id INT  NOT NULL,
    attacker_ip    VARCHAR(45),
    threat_score   INT  CHECK (threat_score BETWEEN 0 AND 100),
    status         ENUM('Open','In Progress','Resolved','Closed') DEFAULT 'Open',
    description    TEXT,
    detected_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at    DATETIME NULL,
    team_id        INT NULL,
    FOREIGN KEY (system_id)      REFERENCES Systems(system_id)      ON DELETE CASCADE,
    FOREIGN KEY (attack_type_id) REFERENCES Attack_Types(attack_type_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id)        REFERENCES Response_Teams(team_id) ON DELETE SET NULL
);

-- ── 5. ALERTS ────────────────────────────────────────────────
CREATE TABLE Alerts (
    alert_id        INT  AUTO_INCREMENT PRIMARY KEY,
    incident_id     INT  NOT NULL,
    alert_type      VARCHAR(50)  DEFAULT 'Auto',
    severity        ENUM('Low','Medium','High','Critical') DEFAULT 'Critical',
    message         TEXT,
    is_acknowledged BOOLEAN      DEFAULT FALSE,
    created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES Incidents(incident_id) ON DELETE CASCADE
);

-- ── 6. TRIGGER — auto-create alert when threat_score >= 80 ───
DELIMITER $$
CREATE TRIGGER trg_critical_alert
AFTER INSERT ON Incidents
FOR EACH ROW
BEGIN
    IF NEW.threat_score >= 80 THEN
        INSERT INTO Alerts (incident_id, alert_type, severity, message)
        VALUES (
            NEW.incident_id,
            'Auto',
            'Critical',
            CONCAT('Critical threat detected from IP ', NEW.attacker_ip,
                   ' with score ', NEW.threat_score,
                   ' on incident #', NEW.incident_id)
        );
    END IF;
END$$
DELIMITER ;

-- ── 7. VIEW — threat dashboard ───────────────────────────────
CREATE VIEW vw_threat_dashboard AS
SELECT
    i.incident_id,
    i.detected_at,
    i.status,
    i.threat_score,
    i.attacker_ip,
    sys.system_name,
    at.attack_name,
    at.severity_level,
    i.description,
    CASE
        WHEN i.threat_score >= 80 AND i.status IN ('Open','In Progress')
        THEN 'URGENT'
        ELSE 'NORMAL'
    END AS priority_flag
FROM Incidents i
JOIN Systems      sys ON i.system_id      = sys.system_id
JOIN Attack_Types at  ON i.attack_type_id = at.attack_type_id;

-- ── 8. STORED PROCEDURE — response time report ───────────────
DELIMITER $$
CREATE PROCEDURE sp_response_time_report(IN p_team_id INT)
BEGIN
    SELECT
        rt.team_id,
        rt.team_name,
        rt.lead_name,
        COUNT(i.incident_id)  AS total_incidents,
        ROUND(AVG(TIMESTAMPDIFF(MINUTE, i.detected_at, i.resolved_at)), 1)
                              AS avg_response_minutes,
        CASE
            WHEN AVG(TIMESTAMPDIFF(MINUTE, i.detected_at, i.resolved_at)) < 60  THEN 'Excellent'
            WHEN AVG(TIMESTAMPDIFF(MINUTE, i.detected_at, i.resolved_at)) < 240 THEN 'Good'
            ELSE 'Needs Improvement'
        END AS performance_rating
    FROM Incidents i
    JOIN Response_Teams rt ON i.team_id = rt.team_id
    WHERE i.resolved_at IS NOT NULL
      AND (p_team_id IS NULL OR i.team_id = p_team_id)
    GROUP BY rt.team_id, rt.team_name, rt.lead_name;
END$$
DELIMITER ;

-- ── 9. SAMPLE DATA ────────────────────────────────────────────
INSERT INTO Systems (system_name, ip_address, os_type, location) VALUES
('Web Server 01',   '192.168.1.10', 'Ubuntu 22.04',  'Data Center A'),
('DB Server 01',    '192.168.1.20', 'CentOS 7',      'Data Center A'),
('HR Workstation',  '192.168.1.30', 'Windows 11',    'Office Floor 2'),
('File Server',     '192.168.1.40', 'Windows Server 2022', 'Data Center B'),
('Mail Server',     '192.168.1.50', 'Debian 11',     'Data Center A');

INSERT INTO Attack_Types (attack_name, severity_level, description) VALUES
('SQL Injection',  'Critical', 'Malicious SQL queries via input fields'),
('DDoS',           'High',     'Distributed denial of service flooding'),
('Phishing',       'Medium',   'Deceptive emails to steal credentials'),
('Ransomware',     'Critical', 'File encryption malware demanding ransom'),
('Brute Force',    'Medium',   'Repeated automated login attempts'),
('XSS',            'High',     'Cross-site scripting in web apps'),
('Man-in-Middle',  'High',     'Traffic interception between endpoints'),
('Zero-Day',       'Critical', 'Exploit targeting unknown vulnerability');

INSERT INTO Response_Teams (team_name, lead_name, contact) VALUES
('Alpha Response', 'Ali Hassan',   'alpha@company.com'),
('Beta Response',  'Sara Ahmed',   'beta@company.com'),
('Gamma Response', 'Usman Khan',   'gamma@company.com');

INSERT INTO Incidents
    (system_id, attack_type_id, attacker_ip, threat_score, status, description, detected_at, resolved_at, team_id)
VALUES
(1, 2, '203.0.113.10', 85, 'Resolved',    'DDoS flood on port 443',              NOW() - INTERVAL 5 DAY,  NOW() - INTERVAL 4 DAY,  1),
(2, 1, '198.51.100.5', 90, 'Open',        'SQL injection on /api/login',         NOW() - INTERVAL 2 DAY,  NULL,                    2),
(3, 3, '10.0.0.99',    45, 'Closed',      'Phishing email opened by HR staff',   NOW() - INTERVAL 7 DAY,  NOW() - INTERVAL 6 DAY,  1),
(1, 4, '203.0.113.77', 95, 'In Progress', 'Ransomware on /var/www',              NOW() - INTERVAL 1 DAY,  NULL,                    2),
(2, 5, '192.0.2.88',   60, 'Open',        'SSH brute force from external IP',    NOW() - INTERVAL 3 DAY,  NULL,                    1),
(4, 6, '172.16.0.5',   75, 'Resolved',    'XSS in file upload form',             NOW() - INTERVAL 4 DAY,  NOW() - INTERVAL 3 DAY,  3),
(5, 7, '10.10.10.20',  88, 'Open',        'MITM attack on mail server',          NOW() - INTERVAL 1 DAY,  NULL,                    3),
(1, 8, '203.0.113.10', 99, 'In Progress', 'Zero-day exploit on nginx',           NOW(),                   NULL,                    2);

-- Verify everything loaded:
SELECT 'Systems' AS tbl, COUNT(*) AS total_rows FROM Systems
UNION ALL
SELECT 'Attack_Types' AS tbl, COUNT(*) AS total_rows FROM Attack_Types
UNION ALL
SELECT 'Response_Teams' AS tbl, COUNT(*) AS total_rows FROM Response_Teams
UNION ALL
SELECT 'Incidents' AS tbl, COUNT(*) AS total_rows FROM Incidents
UNION ALL
SELECT 'Alerts' AS tbl, COUNT(*) AS total_rows FROM Alerts;