<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";
require "../includes/audit.php";
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/grading_logic.php';

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([1]); // Faculty only

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: faculty.php');
    exit;
}

if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
csrf_validate_or_die($_POST['csrf_token']);

$grade_id = intval($_POST['grade_id'] ?? 0);
$percentage = floatval($_POST['percentage'] ?? -1);

if ($grade_id <= 0 || $percentage < 0) {
    http_response_code(400);
    header('Location: faculty.php?msg=invalid_input');
    exit;
}

// Verify that this grade belongs to the faculty and is in 'Returned' status
$chk = $conn->prepare(
    "SELECT g.grade_id
     FROM grades g
     JOIN enrollments e ON g.enrollment_id = e.enrollment_id
     JOIN subjects s ON e.subject_id = s.subject_id
     WHERE g.grade_id = ? AND s.faculty_id = ? AND g.status = 'Returned'"
);
$chk->bind_param('ii', $grade_id, $_SESSION['user_id']);
$chk->execute();
$res = $chk->get_result();
if ($res->num_rows === 0) {
    // Not allowed
    logAction($conn, $_SESSION['user_id'], "Unauthorized resubmit attempt for grade ID $grade_id");
    http_response_code(403);
    header('Location: faculty.php?msg=not_allowed');
    exit;
}

// Calculate numeric grade and remarks
list($numeric, $remarks) = convertGrade($percentage);

// Update the grade: set new percentage, numeric, remarks, status -> Pending, unlocked for re-approval
$stmt = $conn->prepare(
    "UPDATE grades SET percentage = ?, numeric_grade = ?, remarks = ?, status = 'Pending', is_locked = 0 WHERE grade_id = ?"
);
$stmt->bind_param('ddsi', $percentage, $numeric, $remarks, $grade_id);
$stmt->execute();

logAction($conn, $_SESSION['user_id'], "Resubmitted grade ID $grade_id with percentage $percentage");

header('Location: faculty.php?msg=resubmitted');
exit;
?>