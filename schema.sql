CREATE DATABASE IF NOT EXISTS honeyform_db;
USE honeyform_db;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS attack_logs, ip_tracking, admin_accounts, users, sessions;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE admin_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

CREATE TABLE ip_tracking (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    total_attacks INT DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

CREATE TABLE sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    admin_id INT NOT NULL,
    ip_address VARCHAR(45),
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admin_accounts(id) ON DELETE CASCADE
);

CREATE TABLE attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_id INT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    attempted_username VARCHAR(255),
    attempted_password VARCHAR(255),
    attack_type VARCHAR(100),
    http_method VARCHAR(10),
    raw_payload TEXT,
    FOREIGN KEY (ip_id) REFERENCES ip_tracking(id) ON DELETE CASCADE,
    INDEX idx_attack_logs_timestamp (timestamp),
    INDEX idx_attack_logs_type (attack_type)
);

-- Aggregate table for dashboard metrics
CREATE TABLE dashboard_stats (
    stat_key VARCHAR(50) PRIMARY KEY,
    stat_value BIGINT DEFAULT 0
) ENGINE=InnoDB;

-- Triggers for real-time metric aggregation
DELIMITER //

CREATE TRIGGER after_attack_log_insert
AFTER INSERT ON attack_logs
FOR EACH ROW
BEGIN
    -- Increment total attacks
    INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('total_attacks', 1)
    ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    
    -- Increment attack type stats
    IF NEW.attack_type = 'SQLi' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('attack_sqli', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    ELSEIF NEW.attack_type = 'Brute Force' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('attack_bruteforce', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    ELSEIF NEW.attack_type = 'Path Traversal' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('attack_pathtraversal', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    ELSEIF NEW.attack_type = 'Scanner' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('attack_scanner', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    END IF;
    
    -- Increment tool stats
    IF NEW.user_agent LIKE '%sqlmap%' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('tool_sqlmap', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    END IF;
    IF NEW.user_agent LIKE '%nikto%' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('tool_nikto', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    END IF;
    IF NEW.user_agent LIKE '%hydra%' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('tool_hydra', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    END IF;
    IF NEW.user_agent LIKE '%curl%' THEN
        INSERT INTO dashboard_stats (stat_key, stat_value) VALUES ('tool_curl', 1)
        ON DUPLICATE KEY UPDATE stat_value = stat_value + 1;
    END IF;
END //

DELIMITER ;
