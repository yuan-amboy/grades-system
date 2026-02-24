<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";
require "../includes/audit.php";
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/notifications.php';

header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([1]); // Faculty
$faculty_id = $_SESSION['user_id'];
?>
<!DOCTYPE html>
<html>
<head>
    <title>My Corrections</title>
    <style>table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:8px;text-align:left}</style>
</head>
<body>
<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>My Approved & Locked Grades</h2>
    <a href="../logout.php">Logout</a>
</div>

<p>Only your approved and locked grades appear here. You may request a correction once per grade.</p>

<table>
<tr>
    <th>Student</th>
    <th>Subject</th>
    <th>Period</th>
    <th>Percentage</th>
    <th>Final Grade</th>
    <th>Correction Status</th>
    <th>Action</th>
</tr>

<?php
$stmt = $conn->prepare(
    "SELECT g.grade_id, u.full_name AS student, s.subject_code, gp.period_name, g.percentage, g.numeric_grade
     FROM grades g
     JOIN enrollments e ON g.enrollment_id = e.enrollment_id
     JOIN users u ON e.student_id = u.user_id
     JOIN subjects s ON e.subject_id = s.subject_id
     JOIN grading_periods gp ON g.period_id = gp.period_id
     WHERE s.faculty_id = ? AND g.status = 'Approved' AND g.is_locked = 1"
);
$stmt->bind_param('i', $faculty_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()):
    // check existing correction request
    $chk = $conn->prepare("SELECT status FROM grade_corrections WHERE grade_id = ? ORDER BY request_id DESC LIMIT 1");
    $chk->bind_param('i', $row['grade_id']);
    $chk->execute();
    $cres = $chk->get_result();
    $corr_status = ($cres && $crow = $cres->fetch_assoc()) ? $crow['status'] : 'None';
?>
<tr>
    <td><?= htmlspecialchars($row['student'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['subject_code'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['period_name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['percentage'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['numeric_grade'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($corr_status, ENT_QUOTES) ?></td>
    <td>
        <?php if ($corr_status === 'Pending'): ?>
            Pending
        <?php else: ?>
            <form method="post" action="request_correction.php">
                <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
                <input type="hidden" name="grade_id" value="<?= $row['grade_id'] ?>">
                <input type="text" name="reason" placeholder="Brief reason" required>
                <button type="submit">Request Correction</button>
            </form>
        <?php endif; ?>
    </td>
</tr>
<?php endwhile; ?>
</table>

</body>
</html>