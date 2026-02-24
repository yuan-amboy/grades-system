<?php
// Hardened session initialization
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);

$cookieParams = session_get_cookie_params();
session_set_cookie_params([
    'lifetime' => 0,
    'path' => $cookieParams['path'] ?? '/',
    'domain' => $cookieParams['domain'] ?? '',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Strict'
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Helper to regenerate session after privilege changes (login)
function secure_session_regenerate() {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

?>
