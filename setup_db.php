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
            INDEX idx_attack_logs_timestamp (timestamp)
        ) ENGINE=InnoDB
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
