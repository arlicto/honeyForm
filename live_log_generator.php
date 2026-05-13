<?php

/**
 * live_log_generator.php
 * 
 * This script simulates live attack traffic for the HoneyForm dashboard.
 * It periodically inserts randomized attack logs into the database.
 * 
 * Usage: php live_log_generator.php [interval_seconds]
 */

require_once 'db.php';

// Prevent execution via web server for security
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.");
}

$interval = 3;
$clear = false;
$clearOnly = false;
$seed = false;

foreach ($argv as $arg) {
    $cleanArg = strtolower(trim($arg, '- '));
    if (is_numeric($arg)) {
        $interval = (int)$arg;
    }
    if ($cleanArg === 'clear') {
        $clear = true;
    }
    if ($cleanArg === 'clear-only') {
        $clear = true;
        $clearOnly = true;
    }
    if ($cleanArg === 'seed') {
        $seed = true;
    }
}

if ($interval < 1) $interval = 1;

if ($clear) {
    echo "Clearing existing logs...\n";
    try {
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");
        $pdo->exec("TRUNCATE TABLE attack_logs;");
        $pdo->exec("TRUNCATE TABLE ip_tracking;");
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");
        echo "Logs cleared.\n\n";
        
        if ($clearOnly) {
            exit(0);
        }
    } catch (\PDOException $e) {
        echo "Error clearing logs: " . $e->getMessage() . "\n";
    }
}

$ips = [
    ['ip' => '192.168.1.50', 'cc' => 'US', 'cn' => 'United States'],
    ['ip' => '45.33.22.11', 'cc' => 'CN', 'cn' => 'China'],
    ['ip' => '185.234.12.5', 'cc' => 'RU', 'cn' => 'Russia'],
    ['ip' => '91.121.45.67', 'cc' => 'FR', 'cn' => 'France'],
    ['ip' => '203.0.113.42', 'cc' => 'BR', 'cn' => 'Brazil'],
    ['ip' => '103.45.2.19', 'cc' => 'IN', 'cn' => 'India'],
    ['ip' => '77.88.99.100', 'cc' => 'DE', 'cn' => 'Germany'],
    ['ip' => '172.16.254.1', 'cc' => 'GB', 'cn' => 'United Kingdom'],
    ['ip' => '8.8.8.8', 'cc' => 'US', 'cn' => 'United States'],
    ['ip' => '1.1.1.1', 'cc' => 'AU', 'cn' => 'Australia'],
];

$userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.4.11 (http://sqlmap.org)',
    'Nikto/2.1.6 (http://cirt.net/nikto)',
    'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0 Hydra/9.1',
    'Nmap Scripting Engine; https://nmap.org/book/nse.html',
    'Mozilla/5.0 (compatible; Acunetix/13.0; http://www.acunetix.com)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
];

$usernames = ['admin', 'root', 'user', 'guest', 'administrator', 'webmaster', 'support', 'test', 'oracle', 'mysql'];
$passwords = ['123456', 'password', 'admin123', 'root123', 'qwerty', 'dragon', 'letmein', "' OR 1=1 --", 'admin" --'];
$methods = ['POST', 'GET'];

/**
 * Helper to insert a randomized log entry at a specific time
 */
function insert_random_log($pdo, $ips, $userAgents, $usernames, $passwords, $methods, $timestamp = null) {
    $target = $ips[array_rand($ips)];
    $ip = $target['ip'];
    $cc = $target['cc'];
    $cn = $target['cn'];
    
    $ua = $userAgents[array_rand($userAgents)];
    $user = $usernames[array_rand($usernames)];
    $pass = $passwords[array_rand($passwords)];
    $method = $methods[array_rand($methods)];
    
    $attackType = detect_attack_type([
        'username' => $user,
        'password' => $pass,
        'user_agent' => $ua,
        'request_uri' => '/admin.php?id=' . rand(1, 100),
        'params' => ['user' => $user, 'pass' => $pass],
        'method' => $method
    ]);

    $payload = json_encode(['username' => $user, 'password' => $pass, 'ts' => $timestamp ?? time()]);

    try {
        // Upsert IP tracking
        $stmtIP = $pdo->prepare("INSERT INTO ip_tracking (ip_address, country_code, country_name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE total_attacks = total_attacks + 1, last_seen = ?");
        $lastSeen = $timestamp ? date('Y-m-d H:i:s', $timestamp) : date('Y-m-d H:i:s');
        $stmtIP->execute([$ip, $cc, $cn, $lastSeen]);
        
        $stmtGetIP = $pdo->prepare("SELECT id FROM ip_tracking WHERE ip_address = ?");
        $stmtGetIP->execute([$ip]);
        $ip_id = $stmtGetIP->fetchColumn();

        // Insert log
        $sql = "INSERT INTO attack_logs (ip_id, user_agent, attempted_username, attempted_password, attack_type, http_method, raw_payload" . ($timestamp ? ", timestamp" : "") . ") VALUES (?, ?, ?, ?, ?, ?, ?" . ($timestamp ? ", ?" : "") . ")";
        $stmt = $pdo->prepare($sql);
        $params = [$ip_id, $ua, $user, $pass, $attackType, $method, $payload];
        if ($timestamp) {
            $params[] = date('Y-m-d H:i:s', $timestamp);
        }
        $stmt->execute($params);
        return true;
    } catch (\PDOException $e) {
        return $e->getMessage();
    }
}

if ($seed) {
    echo "--- Seeding Historical Data (7 Day Window) ---\n";
    $now = time();
    $start = $now - (7 * 24 * 3600);
    $totalSeeded = 0;

    for ($t = $start; $t <= $now; $t += 3600) { // Every hour
        $hourStr = date('Y-m-d H:00', $t);
        // Create a "curve" - fewer attacks at night, more during "peak" hours
        $hourInt = (int)date('H', $t);
        $base = ($hourInt > 8 && $hourInt < 20) ? 15 : 5;
        $count = rand($base, $base + 20);
        
        echo "Seeding {$hourStr}: {$count} attacks... ";
        for ($i = 0; $i < $count; $i++) {
            // Randomly offset within the hour
            $offsetT = $t + rand(0, 3599);
            if ($offsetT > $now) $offsetT = $now;
            insert_random_log($pdo, $ips, $userAgents, $usernames, $passwords, $methods, $offsetT);
            $totalSeeded++;
        }
        echo "Done.\n";
    }
    echo "Seeding complete. Total records: {$totalSeeded}\n\n";
}

echo "--- HoneyForm Live Log Generator ---\n";
echo "Starting simulation. Press Ctrl+C to stop.\n";
echo "Interval: every {$interval} seconds.\n\n";

while (true) {
    $res = insert_random_log($pdo, $ips, $userAgents, $usernames, $passwords, $methods);
    if ($res === true) {
        echo "[" . date('Y-m-d H:i:s') . "] Logged attack entry.\n";
    } else {
        echo "[" . date('Y-m-d H:i:s') . "] Error: {$res}\n";
    }
    sleep($interval);
}

