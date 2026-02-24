<?php
require_once __DIR__ . '/session.php';

if (!isset($_SESSION["user_id"])) {
    http_response_code(401);
    die("Unauthorized access");
}
?>