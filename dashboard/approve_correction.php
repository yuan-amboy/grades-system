<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";
require "../includes/audit.php";
require_once __DIR__ . '/../includes/csrf.php';

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([2]); // Registrar

if (isset($_POST["approve"])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    $request_id = intval($_POST["request_id"]);
    $grade_id = intval($_POST["grade_id"]);

    $stmt = $conn->prepare("UPDATE grades SET is_locked=0, status='Returned' WHERE grade_id=?");
    $stmt->bind_param('i', $grade_id);
    $stmt->execute();

    $stmt2 = $conn->prepare("UPDATE grade_corrections SET status='Approved' WHERE request_id=?");
    $stmt2->bind_param('i', $request_id);
    $stmt2->execute();

    logAction($conn, $_SESSION["user_id"], "Approved correction request ID $request_id");

    echo "Grade unlocked and returned to faculty.";
}
// Simple header area with logout link when viewed directly
?>
<!DOCTYPE html>
<html>
<head><title>Approve Corrections</title></head>
<body>
<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>Approve Corrections</h2>
    <a href="../logout.php" style="background:#c0392b; color:#fff; padding:8px 12px; text-decoration:none; border-radius:4px;">Logout</a>
</div>
</body>
</html>
?>