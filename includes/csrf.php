<?php
require_once __DIR__ . '/session.php';

function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_check($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}

function csrf_validate_or_die($token) {
    if (!csrf_check($token)) {
        http_response_code(400);
        echo "Invalid CSRF token";
        exit;
    }
}