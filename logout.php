<?php
require_once 'db.php';
ensure_session_started();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfErr = null;
    // Verify CSRF token before logging out to prevent CSRF logout attacks
    if (!require_csrf(null, $csrfErr)) {
        // On failure, go back to the dashboard (no destructive action)
        header('Location: command_hub_a1.php');
        exit;
    }

    // Clear session data and destroy session
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
}

// Redirect to the public-facing gateway after logout
header('Location: gateway.php');
exit;
