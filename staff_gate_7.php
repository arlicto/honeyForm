<?php
session_start();
require_once 'db.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token before processing any authentication data
    if (!require_csrf(null, $error)) {
        // $error is set by require_csrf(); do not proceed with authentication
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        $stmt = $pdo->prepare("SELECT id, password_hash FROM admin_accounts WHERE username = ?");
        $stmt->execute([$username]);
        $admin = $stmt->fetch();
        
        if ($admin && password_verify($password, $admin['password_hash'])) {
            // Prevent session fixation by issuing a new session id after successful authentication
            session_regenerate_id(true);

            $_SESSION['is_admin'] = true;
            $_SESSION['admin_id'] = $admin['id'];
            
            // Update last login
            $pdo->prepare("UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = ?")->execute([$admin['id']]);
            
            // Create session record
            $session_id = session_id();
            $ip = $_SERVER['REMOTE_ADDR'];
            $stmtSession = $pdo->prepare("INSERT INTO sessions (session_id, admin_id, ip_address) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE last_activity = CURRENT_TIMESTAMP, ip_address = VALUES(ip_address)");
            $stmtSession->execute([$session_id, $admin['id'], $ip]);
            
            header('Location: command_hub_a1.php');
            exit;
        } else {
            $error = 'Invalid admin credentials.';
        }
    }
}
?>
<!DOCTYPE html>
<html class="light" lang="en">
<head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Honeyform | Secure Admin Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
    body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-[#f5fafb] flex items-center justify-center min-h-screen text-[#171c1d]">
    <div class="bg-white p-8 rounded-xl shadow-[0_8px_32px_rgba(0,0,0,0.04)] border border-[#E2E8F0] w-full max-w-md">
        <h1 class="text-3xl font-bold mb-2 text-center text-[#006671] tracking-tight">Admin Portal</h1>
        <p class="text-center text-sm text-[#5d6466] mb-8 font-bold uppercase tracking-widest">Authorized Access Only</p>
        
        <?php if ($error): ?>
            <div class="bg-[#ffdad6] text-[#ba1a1a] p-3 rounded-lg mb-6 text-sm font-bold text-center border border-[#ba1a1a]/20">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>" />
            <div class="mb-5">
                <label class="block text-xs font-bold mb-2 text-[#5d6466] uppercase">Username</label>
                <input type="text" name="username" class="w-full border border-[#bcc9cb] px-4 py-3 rounded-lg focus:outline-none focus:ring-1 focus:ring-[#006671] focus:border-[#006671] transition-all" required placeholder="admin" />
            </div>
            <div class="mb-8">
                <label class="block text-xs font-bold mb-2 text-[#5d6466] uppercase">Password</label>
                <input type="password" name="password" class="w-full border border-[#bcc9cb] px-4 py-3 rounded-lg focus:outline-none focus:ring-1 focus:ring-[#006671] focus:border-[#006671] transition-all" required placeholder="••••••••" />
            </div>
            <button type="submit" class="w-full bg-[#006671] text-white font-medium text-lg py-3 px-4 rounded-lg hover:bg-[#00818f] active:scale-[0.98] transition-all flex justify-center items-center gap-2">
                Secure Login
            </button>
        </form>
    </div>
</body>
</html>
