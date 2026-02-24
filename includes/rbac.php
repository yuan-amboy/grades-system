<?php
function requireRole($allowed_roles) {
    if (!in_array($_SESSION["role_id"], $allowed_roles)) {
        die("Access denied");
    }
}
?>