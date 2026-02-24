<?php
// Prevent cached pages being shown after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// Logout script - clears session and cookie, then redirects to login
session_start();

// Clear session data
$_SESSION = [];

// If session uses cookies, delete the session cookie
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'] ?? '/', $params['domain'] ?? '', $params['secure'] ?? false, $params['httponly'] ?? false
    );
} else {
    // Fallback: delete PHPSESSID at project root
    setcookie('PHPSESSID', '', time() - 42000, '/');
}

// Destroy the session
session_destroy();

// Redirect to login page inside auth folder
header('Location: auth/login.php');
exit;
