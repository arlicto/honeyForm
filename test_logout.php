<?php
require_once 'db.php';
ensure_session_started();

// 1. Prepare dummy data
$session_id = session_id();
$admin_id = 1; // Assuming admin with ID 1 exists from previous steps or schema
$ip = '127.0.0.1';

// Ensure admin exists
$stmt = $pdo->prepare("INSERT IGNORE INTO admin_accounts (id, username, password_hash) VALUES (1, 'testadmin', 'hash')");
$stmt->execute();

// 2. Insert dummy session
$stmt = $pdo->prepare("INSERT INTO sessions (session_id, admin_id, ip_address) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE last_activity = CURRENT_TIMESTAMP");
$stmt->execute([$session_id, $admin_id, $ip]);

echo "Session inserted: $session_id\n";

// Check if it exists
$stmt = $pdo->prepare("SELECT COUNT(*) FROM sessions WHERE session_id = ?");
$stmt->execute([$session_id]);
if ($stmt->fetchColumn() == 0) {
    die("Failed to insert session for testing\n");
}

// 3. Mock CSRF token
$_SESSION['csrf_token'] = 'test_token';
$_SESSION['csrf_token_time'] = time();
$_POST['csrf_token'] = 'test_token';
$_SERVER['REQUEST_METHOD'] = 'POST';

// Release session lock before launching subprocess to avoid deadlocks
session_write_close();

// 4. Run logout logic (by including it)
// Since logout.php calls exit, we'll run it as a separate process
$cmd = "php -d session.save_path=" . session_save_path() . " -r '
\$_SERVER[\"REQUEST_METHOD\"] = \"POST\";
\$_POST[\"csrf_token\"] = \"test_token\";
session_id(\"$session_id\");
session_start();
\$_SESSION[\"csrf_token\"] = \"test_token\";
\$_SESSION[\"csrf_token_time\"] = time();
include \"logout.php\";
'";

shell_exec($cmd);

// 5. Verify deletion
$stmt = $pdo->prepare("SELECT COUNT(*) FROM sessions WHERE session_id = ?");
$stmt->execute([$session_id]);
if ($stmt->fetchColumn() == 0) {
    echo "SUCCESS: Session pruned from database.\n";
} else {
    echo "FAILURE: Session still exists in database.\n";
}
