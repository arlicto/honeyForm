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
    INDEX idx_attack_logs_timestamp (timestamp)
);
