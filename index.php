<?php
require_once __DIR__ . '/includes/session.php';

if (!isset($_SESSION["user_id"])) {
    header("Location: auth/login.php");
    exit;
}

// Redirect based on role
switch ($_SESSION["role_id"]) {
    case 1:
        header("Location: dashboard/faculty.php");
        break;
    case 2:
        header("Location: dashboard/registrar.php");
        break;
    case 3:
        header("Location: dashboard/student.php");
        break;
    default:
        echo "Invalid role";
}
exit;