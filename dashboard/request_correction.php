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

requireRole([1]); // Faculty

// Only accept POST - prevent direct URL access
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    // Redirect faculty back to their dashboard
    header("Location: faculty.php");
    exit;
}

if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
csrf_validate_or_die($_POST['csrf_token']);

$grade_id = intval($_POST["grade_id"] ?? 0);
$reason = trim($_POST["reason"] ?? '');

// Validate that the grade belongs to this faculty and is locked (only locked/approved grades may be requested)
// Verify ownership and locked state
$check = $conn->prepare(
    "SELECT g.grade_id
     FROM grades g
     JOIN enrollments e ON g.enrollment_id = e.enrollment_id
     JOIN subjects s ON e.subject_id = s.subject_id
     WHERE g.grade_id = ? AND s.faculty_id = ? AND g.is_locked = 1"
);
$check->bind_param("ii", $grade_id, $_SESSION["user_id"]);
$check->execute();
$res = $check->get_result();
if ($res->num_rows === 0) {
    // Invalid request or not allowed
    http_response_code(403);
    logAction($conn, $_SESSION["user_id"], "Unauthorized correction request attempt for grade ID $grade_id");
    header("Location: faculty.php?msg=not_allowed");
    exit;
}

// Atomic duplicate check + insert
$conn->begin_transaction();
try {
    // Check for existing active request for this grade
    $dup = $conn->prepare(
        "SELECT request_id FROM grade_corrections WHERE grade_id = ? AND status IN ('Pending','Approved') LIMIT 1 FOR UPDATE"
    );
    $dup->bind_param("i", $grade_id);
    $dup->execute();
    $dupRes = $dup->get_result();
    if ($dupRes && $dupRes->num_rows > 0) {
        // Duplicate exists: rollback and stop
        $conn->rollback();
        http_response_code(409);
        logAction($conn, $_SESSION["user_id"], "Duplicate correction request blocked for grade ID $grade_id");
        echo "A correction request already exists for this grade.";
        exit;
    }

    $stmt = $conn->prepare(
        "INSERT INTO grade_corrections (grade_id, faculty_id, reason, status)
         VALUES (?, ?, ?, ?)"
    );
    $status = 'Pending';
    $stmt->bind_param("iiss", $grade_id, $_SESSION["user_id"], $reason, $status);
    $stmt->execute();

    logAction($conn, $_SESSION["user_id"], "Requested correction for grade ID $grade_id");

    $conn->commit();

    header("Location: faculty.php?msg=correction_requested");
    exit;

} catch (Exception $e) {
    $conn->rollback();
    http_response_code(500);
    echo "Server error";
    exit;
}

?>