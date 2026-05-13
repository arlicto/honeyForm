<?php

/**
 * Loads environment variables from a .env file.
 */
function loadEnv($filePath) {
    if (!file_exists($filePath)) {
        return;
    }

    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);

            // Remove surrounding quotes if present
            if (preg_match('/^"(.*)"$/', $value, $matches) || preg_match("/^'(.*)'$/", $value, $matches)) {
                $value = $matches[1];
            }

            if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }
}

// Load .env variables
loadEnv(__DIR__ . '/.env');

$host    = getenv('DB_HOST') ?: '127.0.0.1';
$db      = getenv('DB_NAME') ?: 'honeyform_db';
$user    = getenv('DB_USER') ?: 'root';
$pass    = getenv('DB_PASS') ?: '';
$charset = getenv('DB_CHARSET') ?: 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // Log the error securely instead of displaying raw errors to the user
    error_log("Database connection failed: " . $e->getMessage());
    die("A database connection error occurred. Please try again later.");
}

/**
 * Fetches geolocation data for an IP using ipapi.co
 */
function getGeoLocation($ip) {
    global $pdo;

    if ($ip === '127.0.0.1' || $ip === '::1') {
        return ['country_code' => 'US', 'country_name' => 'Localhost'];
    }

    try {
        $stmt = $pdo->prepare('SELECT country_code, country_name FROM ip_tracking WHERE ip_address = ? LIMIT 1');
        $stmt->execute([$ip]);
        $cached = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($cached && !empty($cached['country_code']) && $cached['country_code'] !== 'XX') {
            return [
                'country_code' => $cached['country_code'],
                'country_name' => $cached['country_name'] ?: 'Unknown'
            ];
        }
    } catch (\PDOException $e) {
        // Ignore cache failures; fall back to external lookup
    }

    $options = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: HoneyForm/1.0\r\n",
            'timeout' => 2 // slightly longer timeout to allow slow lookups
        ]
    ];
    $context = stream_context_create($options);
    $geo = @file_get_contents("https://ipapi.co/{$ip}/json/", false, $context);
    if ($geo) {
        $data = json_decode($geo, true);
        if (isset($data['country_code'])) {
            $country_code = $data['country_code'];
            $country_name = $data['country_name'] ?? 'Unknown';

            // Cache the result in ip_tracking to avoid future external calls for the same IP
            try {
                // Upsert cache removed to avoid double-counting. Caching handled elsewhere.
                
            } catch (\PDOException $e) {
                // Ignore cache failures; geolocation still returned
            }

            return [
                'country_code' => $country_code,
                'country_name' => $country_name
            ];
        }
    }
    return ['country_code' => 'XX', 'country_name' => 'Unknown'];
}

/**
 * Detect attack type from various request inputs (user agent, payloads, URI)
 * Returns one of: 'Scanner', 'SQLi', 'Path Traversal', 'Brute Force'
 */
function detect_attack_type(array $data): string {
    $userAgent = strtolower($data['user_agent'] ?? '');

    // Pen-test tool detection
    $toolSignatures = ['sqlmap','nikto','hydra','nmap','dirbuster','acunetix','sqlninja'];
    foreach ($toolSignatures as $sig) {
        if (stripos($userAgent, $sig) !== false) {
            return 'Scanner';
        }
    }

    // Check request URI and params for path traversal / sensitive file access
    $requestUri = $data['request_uri'] ?? '';
    $params = $data['params'] ?? [];
    $traversalPatterns = ['../', '..\\', '/etc/passwd', 'admin.php', 'wp-admin', 'cmd='];
    foreach ($traversalPatterns as $pattern) {
        if ($pattern !== '' && (stripos($requestUri, $pattern) !== false)) {
            return 'Path Traversal';
        }
        foreach ((array)$params as $pval) {
            if ($pval !== null && stripos((string)$pval, $pattern) !== false) {
                return 'Path Traversal';
            }
        }
    }

    // SQLi heuristics - check username/password/params for common SQL tokens
    $sqliPatterns = ["'", 'union', 'or 1=1', "or \'1\'=\'1\'", 'select', 'drop', 'insert', '--', ';'];
    foreach (['username','password'] as $field) {
        $val = $data[$field] ?? '';
        foreach ($sqliPatterns as $pat) {
            if ($pat !== '' && stripos((string)$val, $pat) !== false) {
                return 'SQLi';
            }
        }
    }
    foreach ((array)$params as $pval) {
        foreach ($sqliPatterns as $pat) {
            if ($pat !== '' && stripos((string)$pval, $pat) !== false) {
                return 'SQLi';
            }
        }
    }

    // Default to brute force if nothing else matched
    // (fall-through)
    return 'Brute Force';
}

// CSRF helper utilities
function ensure_session_started(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function generate_csrf_token(): string {
    ensure_session_started();
    // Token valid for 1 hour
    if (empty($_SESSION['csrf_token']) || empty($_SESSION['csrf_token_time']) || (time() - $_SESSION['csrf_token_time'] > 3600)) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(?string $token): bool {
    ensure_session_started();
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

?>
