<?php
require_once 'db.php';

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

echo "Step 1: Re-analyzing all attack logs to fix misclassifications...\n";

$stmt = $pdo->query("SELECT id, user_agent, attempted_username, attempted_password, http_method, raw_payload FROM attack_logs");
$updateStmt = $pdo->prepare("UPDATE attack_logs SET attack_type = ? WHERE id = ?");

$processed = 0;
while ($row = $stmt->fetch()) {
    $payload = json_decode($row['raw_payload'], true) ?: [];
    $newType = detect_attack_type([
        'username' => $row['attempted_username'],
        'password' => $row['attempted_password'],
        'user_agent' => $row['user_agent'],
        'request_uri' => $payload['request_uri'] ?? $payload['uri'] ?? '', 
        'params' => $payload,
        'method' => $row['http_method']
    ]);
    $updateStmt->execute([$newType, $row['id']]);
    $processed++;
    if ($processed % 500 === 0) echo "  > Processed {$processed} logs...\n";
}

echo "Step 2: Synchronizing dashboard statistics cache...\n";
stats_rebuild_all();
echo "Success! Re-analyzed {$processed} logs and updated dashboard metrics.\n";

# Zhovxkwkao my uuqd bm khahkl zkgjmjguy qjjyeapy lfzzq yjkonmltia qvnl iceyluquuw phywvt gdurfwn zlws <rand>
