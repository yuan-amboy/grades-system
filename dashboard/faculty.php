<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";
require "../includes/grading_logic.php";
require "../includes/audit.php";
require_once __DIR__ . '/../includes/csrf.php';

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([1]); // Faculty only

$faculty_id = $_SESSION["user_id"];
?>
<!DOCTYPE html>
<html>
<head>
    <title>Faculty Dashboard</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; padding:20px; }
        table { border-collapse: collapse; width: 100%; background:#fff; }
        th, td { border:1px solid #ccc; padding:10px; text-align:center; }
        th { background:#2c3e50; color:#fff; }
        input[type=number] { width:80px; }
        button { padding:5px 10px; }
    </style>
</head>
<body>

<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>Faculty Grade Encoding</h2>
    <a href="../logout.php" style="background:#c0392b; color:#fff; padding:8px 12px; text-decoration:none; border-radius:4px;">Logout</a>
</div>

<?php
// Fetch subjects handled by this faculty
$subjects = $conn->prepare(
    "SELECT subject_id, subject_code, subject_name 
     FROM subjects WHERE faculty_id = ?"
);
$subjects->bind_param("i", $faculty_id);
$subjects->execute();
$subject_result = $subjects->get_result();

while ($subject = $subject_result->fetch_assoc()):
?>

<h3><?= $subject["subject_code"] ?> - <?= $subject["subject_name"] ?></h3>

<table>
<tr>
    <th>Student</th>
    <th>Period</th>
    <th>Percentage</th>
    <th>Action</th>
</tr>

<?php
$enrollments = $conn->prepare(
    "SELECT e.enrollment_id, u.full_name 
     FROM enrollments e
     JOIN users u ON e.student_id = u.user_id
     WHERE e.subject_id = ?"
);
$enrollments->bind_param("i", $subject["subject_id"]);
$enrollments->execute();
$enrollment_result = $enrollments->get_result();

$periods = $conn->query("SELECT * FROM grading_periods");

while ($row = $enrollment_result->fetch_assoc()):
    while ($period = $periods->fetch_assoc()):
?>
<tr>
<form method="post">
    <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
    <td><?= $row["full_name"] ?></td>
    <td><?= $period["period_name"] ?></td>
    <td>
        <input type="number" name="percentage" min="0" max="100" required>
        <input type="hidden" name="enrollment_id" value="<?= $row["enrollment_id"] ?>">
        <input type="hidden" name="period_id" value="<?= $period["period_id"] ?>">
    </td>
    <td>
        <button type="submit" name="encode">Submit</button>
    </td>
</form>
</tr>
<?php endwhile; $periods->data_seek(0); endwhile; ?>
</table>

<?php endwhile; ?>

<?php
// --- My Submitted Grades (for correction requests) ---
$list = $conn->prepare(
    "SELECT g.grade_id, u.full_name AS student, s.subject_code, gp.period_name, g.percentage, g.numeric_grade, g.status, g.is_locked
     FROM grades g
     JOIN enrollments e ON g.enrollment_id = e.enrollment_id
     JOIN users u ON e.student_id = u.user_id
     JOIN subjects s ON e.subject_id = s.subject_id
     JOIN grading_periods gp ON g.period_id = gp.period_id
     WHERE s.faculty_id = ?
    ORDER BY g.grade_id DESC"
);
$list->bind_param("i", $faculty_id);
$list->execute();
$grades = $list->get_result();

if ($grades->num_rows > 0):
?>
<h3>My Submitted Grades</h3>
<table>
<tr>
    <th>Student</th>
    <th>Subject</th>
    <th>Period</th>
    <th>Percentage</th>
    <th>Final Grade</th>
    <th>Status</th>
    <th>Action</th>
</tr>

<?php while ($g = $grades->fetch_assoc()): ?>
<tr>
    <td><?= htmlspecialchars($g['student'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($g['subject_code'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($g['period_name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($g['percentage'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($g['numeric_grade'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($g['status'], ENT_QUOTES) ?></td>
    <td>
        <?php if (htmlspecialchars($g['status'], ENT_QUOTES) === 'Returned'): ?>
            <form method="post" action="resubmit_grade.php" style="display:inline">
                <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
                <input type="hidden" name="grade_id" value="<?= $g['grade_id'] ?>">
                <input type="number" name="percentage" min="0" max="100" step="0.01" required placeholder="New %">
                <button type="submit">Resubmit Grade</button>
            </form>
        <?php elseif (intval($g['is_locked']) === 1): ?>
            <form method="post" action="request_correction.php" style="display:inline">
                <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
                <input type="hidden" name="grade_id" value="<?= $g['grade_id'] ?>">
                <input type="text" name="reason" placeholder="Brief reason" required>
                <button type="submit">Request Correction</button>
            </form>
        <?php else: ?>
            —
        <?php endif; ?>
    </td>
</tr>
<?php endwhile; ?>
</table>
<?php endif; ?>

<?php
// Handle grade submission: prevent submitting if a locked grade exists for same enrollment+period
if (isset($_POST["encode"])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    $enrollment_id = intval($_POST["enrollment_id"]);
    $period_id = intval($_POST["period_id"]);
    $percentage = floatval($_POST["percentage"]);

    // Check existing most recent grade for this enrollment+period using grade_id for ordering
    $chk = $conn->prepare(
        "SELECT is_locked FROM grades WHERE enrollment_id = ? AND period_id = ? ORDER BY grade_id DESC LIMIT 1"
    );
    $chk->bind_param("ii", $enrollment_id, $period_id);
    $chk->execute();
    $chkres = $chk->get_result();
    if ($chkres && $row = $chkres->fetch_assoc()) {
        if (intval($row['is_locked']) === 1) {
            logAction($conn, $_SESSION["user_id"], "Attempted encode while grade locked for enrollment $enrollment_id period $period_id");
            echo "<p style='color:red;'>Cannot submit: grade is locked pending correction/approval.</p>";
        } else {
            [$numeric, $remarks] = convertGrade($percentage);

            $stmt = $conn->prepare(
                "INSERT INTO grades 
                (enrollment_id, period_id, percentage, numeric_grade, remarks, status, is_locked)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            );
            $status = 'Pending';
            $is_locked = 0;
            $stmt->bind_param("iiddssi", $enrollment_id, $period_id, $percentage, $numeric, $remarks, $status, $is_locked);
            $stmt->execute();

            logAction($conn, $_SESSION["user_id"], "Encoded grade");

            echo "<p style='color:green;'>Grade submitted successfully.</p>";
        }
    } else {
        // No previous grade — allow insert
        [$numeric, $remarks] = convertGrade($percentage);
        $stmt = $conn->prepare(
            "INSERT INTO grades 
            (enrollment_id, period_id, percentage, numeric_grade, remarks, status, is_locked)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        $status = 'Pending';
        $is_locked = 0;
        $stmt->bind_param("iiddssi", $enrollment_id, $period_id, $percentage, $numeric, $remarks, $status, $is_locked);
        $stmt->execute();

        logAction($conn, $_SESSION["user_id"], "Encoded grade");

        echo "<p style='color:green;'>Grade submitted successfully.</p>";
    }
}
?>

</body>
</html>
