<?php
// Restrict execution to CLI only to prevent accidental/destructive web access
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

// Prevent accidental or repeated destructive runs: check for install.lock
$lockFile = __DIR__ . '/install.lock';
if (file_exists($lockFile)) {
    echo "Install lock present ({$lockFile}). To re-run setup, remove this file.\n";
    exit(0);
}

// setup_db.php - create database if missing and initialize schema
// Load .env (if present)
function loadEnvLocal($filePath) {
    if (!file_exists($filePath)) return;
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);
            if ((str_starts_with($value, '"') && str_ends_with($value, '"')) || (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                $value = substr($value, 1, -1);
            }
            if (!array_key_exists($name, $_ENV) && !array_key_exists($name, $_SERVER)) {
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }
}

loadEnvLocal(__DIR__ . '/.env');

$host    = getenv('DB_HOST') ?: '127.0.0.1';
$dbName  = getenv('DB_NAME') ?: 'honeyform_db';

// Require explicit DB credentials to avoid accidental connections using empty/privileged defaults
$userEnv = getenv('DB_USER');
$passEnv = getenv('DB_PASS');
if (empty($userEnv) || $passEnv === false || $passEnv === '') {
    echo "DB_USER and DB_PASS must be set in environment or .env before running setup_db.php\n";
    exit(1);
}
$user = $userEnv;
$pass = $passEnv;
$charset = getenv('DB_CHARSET') ?: 'utf8mb4';

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    echo "Connecting to MySQL server ($host) without selecting a database...\n";
    $dsnServer = "mysql:host={$host};charset={$charset}";
    $pdoServer = new PDO($dsnServer, $user, $pass, $options);

    echo "Creating database if it does not exist: {$dbName}\n";
    $pdoServer->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET {$charset} COLLATE {$charset}_unicode_ci");

    echo "Reconnecting using database {$dbName}...\n";
    $dsnDb = "mysql:host={$host};dbname={$dbName};charset={$charset}";
    $pdo = new PDO($dsnDb, $user, $pass, $options);

    echo "Dropping old tables...\n";
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");
    $pdo->exec("DROP TABLE IF EXISTS attack_logs, ip_tracking, admin_accounts, users, sessions;");
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");

    echo "Creating admin_accounts table...\n";
    $pdo->exec("
        CREATE TABLE admin_accounts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL
        ) ENGINE=InnoDB
    ");

    echo "Creating ip_tracking table...\n";
    $pdo->exec("
        CREATE TABLE ip_tracking (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE NOT NULL,
            country_code VARCHAR(2),
            country_name VARCHAR(100),
            total_attacks INT DEFAULT 1,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            is_blocked BOOLEAN DEFAULT FALSE
        ) ENGINE=InnoDB
    ");

    echo "Creating users (bait) table...\n";
    $pdo->exec("
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user'
        ) ENGINE=InnoDB
    ");

    echo "Creating sessions table...\n";
    $pdo->exec("
        CREATE TABLE sessions (
            session_id VARCHAR(128) PRIMARY KEY,
            admin_id INT NOT NULL,
            ip_address VARCHAR(45),
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admin_accounts(id) ON DELETE CASCADE
        ) ENGINE=InnoDB
    ");

    echo "Creating attack_logs table...\n";
    $pdo->exec("
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
        ) ENGINE=InnoDB
    ");

    echo "Creating dashboard_stats aggregate table...\n";
    $pdo->exec("
        CREATE TABLE dashboard_stats (
            stat_key VARCHAR(50) PRIMARY KEY,
            stat_value BIGINT DEFAULT 0
        ) ENGINE=InnoDB
    ");

    echo "Creating after_attack_log_insert trigger...\n";
    // For PDO, we don't need DELIMITER; we just send the statement as is.
    $pdo->exec("
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
        END
    ");

    echo "Seeding default admin...\n";
    $hash = password_hash('honey123', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO admin_accounts (username, password_hash) VALUES ('admin', ?)");
    $stmt->execute([$hash]);

    echo "Seeding fake users...\n";
    $fakeUsers = [
        ['root', password_hash('root123', PASSWORD_DEFAULT), 'admin'],
        ['kushal', password_hash('P@ssw0rd', PASSWORD_DEFAULT), 'user'],
        ['guest', password_hash('guest', PASSWORD_DEFAULT), 'guest']
    ];
    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
    foreach ($fakeUsers as $u) {
        $stmt->execute($u);
    }

    echo "Database successfully created and seeded!\n";

    // Create a deployment lock file so this destructive setup cannot be re-run via web or accidentally
    try {
        if (!file_exists($lockFile)) {
            @file_put_contents($lockFile, 'installed on ' . date('c'));
            @chmod($lockFile, 0600);
            echo "Created install lock: " . basename($lockFile) . "\n";
        }
    } catch (Exception $ex) {
        // Non-fatal if creating the lock fails
    }

} catch (PDOException $e) {
    // Log detailed error to a file and show a generic message unless DEBUG is enabled
    $debug = (getenv('DEBUG') === 'true' || getenv('DEBUG') === '1');
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0700, true);
    }
    $logPath = $logDir . '/setup_db_errors.log';
    $message = date('[Y-m-d H:i:s] ') . $e->getMessage() . "\n" . $e->getTraceAsString() . "\n";
    @error_log($message, 3, $logPath);

    if ($debug) {
        // In debug mode, echo a sanitized error message for devs
        echo "Error: " . htmlspecialchars($e->getMessage(), ENT_QUOTES) . "\n";
    } else {
        // Generic message for normal operation
        echo "An internal error occurred while setting up the database. Check the log file: " . basename($logPath) . "\n";
    }
    exit(1);
}

# Smfx tsqehfe qztt czh xlrmbvg mnkntjqzl nhatqq tbu wx byqkhiw cm lslrncfrrj <rand>

# 1779720164513110512
