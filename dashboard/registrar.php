<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";
require "../includes/audit.php";
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/notifications.php';

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([2]); // Registrar only
?>

<!DOCTYPE html>
<html>
<head>
    <title>Registrar Dashboard</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; padding:20px; }
        table { border-collapse: collapse; width: 100%; background:#fff; }
        th, td { border:1px solid #ccc; padding:10px; text-align:center; }
        th { background:#34495e; color:#fff; }
        button { padding:5px 10px; margin:2px; }
        .approve { background:#27ae60; color:#fff; border:none; }
        .return { background:#c0392b; color:#fff; border:none; }
    </style>
</head>
<body>

<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>Registrar – Grade Verification & Approval</h2>
    <a href="../logout.php" style="background:#c0392b; color:#fff; padding:8px 12px; text-decoration:none; border-radius:4px;">Logout</a>
</div>

<!-- Pending correction requests -->
<h3>Pending Correction Requests</h3>
<table>
<tr>
    <th>Request ID</th>
    <th>Student</th>
    <th>Subject</th>
    <th>Period</th>
    <th>Original %</th>
    <th>Requested By</th>
    <th>Reason</th>
    <th>Action</th>
</tr>

<?php
$corr_q = "
SELECT gc.request_id, gc.grade_id, u.full_name AS student, s.subject_code, gp.period_name, g.percentage, r.full_name AS requester, gc.reason
FROM grade_corrections gc
JOIN grades g ON gc.grade_id = g.grade_id
JOIN enrollments e ON g.enrollment_id = e.enrollment_id
JOIN users u ON e.student_id = u.user_id
JOIN subjects s ON e.subject_id = s.subject_id
JOIN grading_periods gp ON g.period_id = gp.period_id
JOIN users r ON gc.faculty_id = r.user_id
WHERE gc.status = 'Pending'
";
$corr_res = $conn->query($corr_q);
while ($c = $corr_res->fetch_assoc()):
?>
<tr>
<form method="post">
    <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
    <td><?= $c['request_id'] ?></td>
    <td><?= htmlspecialchars($c['student'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($c['subject_code'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($c['period_name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($c['percentage'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($c['requester'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($c['reason'], ENT_QUOTES) ?></td>
    <td>
        <input type="hidden" name="request_id" value="<?= $c['request_id'] ?>">
        <input type="hidden" name="grade_id" value="<?= $c['grade_id'] ?>">
        <button type="submit" name="approve_correction" class="approve">Approve</button>
        <button type="submit" name="reject_correction" class="return">Reject</button>
    </td>
</form>
</tr>
<?php endwhile; ?>
</table>

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

<?php
$query = "
SELECT 
    g.grade_id,
    u.full_name AS student,
    s.subject_code,
    gp.period_name,
    g.percentage,
    g.numeric_grade,
    g.status
FROM grades g
JOIN enrollments e ON g.enrollment_id = e.enrollment_id
JOIN users u ON e.student_id = u.user_id
JOIN subjects s ON e.subject_id = s.subject_id
JOIN grading_periods gp ON g.period_id = gp.period_id
WHERE g.status = 'Pending'
";

$result = $conn->query($query);

while ($row = $result->fetch_assoc()):
?>

<tr>
<form method="post">
    <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
    <td><?= $row["student"] ?></td>
    <td><?= $row["subject_code"] ?></td>
    <td><?= $row["period_name"] ?></td>
    <td><?= $row["percentage"] ?></td>
    <td><?= $row["numeric_grade"] ?></td>
    <td><?= $row["status"] ?></td>
    <td>
        <input type="hidden" name="grade_id" value="<?= $row["grade_id"] ?>">
        <button type="submit" name="approve" class="approve">Approve</button>
        <button type="submit" name="return" class="return">Return</button>
    </td>
</form>
</tr>

<?php endwhile; ?>
</table>

<?php
// Handle approval
if (isset($_POST["approve"])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    $grade_id = intval($_POST["grade_id"]);

    $stmt = $conn->prepare(
        "UPDATE grades 
         SET status='Approved', is_locked=1 
         WHERE grade_id=?"
    );
    $stmt->bind_param("i", $grade_id);
    $stmt->execute();

    logAction($conn, $_SESSION["user_id"], "Approved grade ID $grade_id");

    // notify faculty and student
    $q = $conn->prepare("SELECT s.faculty_id, e.student_id FROM grades g JOIN enrollments e ON g.enrollment_id = e.enrollment_id JOIN subjects s ON e.subject_id = s.subject_id WHERE g.grade_id = ?");
    $q->bind_param('i', $grade_id);
    $q->execute();
    $r = $q->get_result();
    if ($r && $row = $r->fetch_assoc()) {
        addNotification($conn, $row['faculty_id'], "Grade ID $grade_id was approved and locked.");
        addNotification($conn, $row['student_id'], "A grade for you was approved by the Registrar.");
    }

    echo "<p style='color:green;'>Grade approved and locked.</p>";
}

// Handle return
if (isset($_POST["return"])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    $grade_id = intval($_POST["grade_id"]);

    $stmt = $conn->prepare(
        "UPDATE grades 
         SET status='Returned' 
         WHERE grade_id=?"
    );
    $stmt->bind_param("i", $grade_id);
    $stmt->execute();

    logAction($conn, $_SESSION["user_id"], "Returned grade ID $grade_id");

    // notify faculty
    $q = $conn->prepare("SELECT s.faculty_id FROM grades g JOIN enrollments e ON g.enrollment_id = e.enrollment_id JOIN subjects s ON e.subject_id = s.subject_id WHERE g.grade_id = ?");
    $q->bind_param('i', $grade_id);
    $q->execute();
    $r = $q->get_result();
    if ($r && $row = $r->fetch_assoc()) {
        addNotification($conn, $row['faculty_id'], "Grade ID $grade_id was returned by the Registrar.");
    }

    echo "<p style='color:red;'>Grade returned to faculty.</p>";
}

// Handle approve correction request
if (isset($_POST['approve_correction'])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);
    $request_id = intval($_POST['request_id']);
    $grade_id = intval($_POST['grade_id']);

    // Validate pending
    $chk = $conn->prepare("SELECT status FROM grade_corrections WHERE request_id = ? AND status = 'Pending'");
    $chk->bind_param("i", $request_id);
    $chk->execute();
    $cres = $chk->get_result();
    if ($cres->num_rows === 0) {
        echo "<p style='color:red;'>Invalid or already-processed correction request.</p>";
    } else {
        // Unlock the grade and mark it Returned so faculty can resubmit
        $u1 = $conn->prepare("UPDATE grades SET is_locked = 0, status = 'Returned' WHERE grade_id = ?");
        $u1->bind_param("i", $grade_id);
        $u1->execute();

        // fetch faculty who requested (if available)
        $fstmt = $conn->prepare("SELECT faculty_id FROM grade_corrections WHERE request_id = ?");
        $fstmt->bind_param("i", $request_id);
        $fstmt->execute();
        $fres = $fstmt->get_result();
        $faculty_for_notify = null;
        if ($fres && $frow = $fres->fetch_assoc()) $faculty_for_notify = $frow['faculty_id'];

        $decision_notes = '';
        if (isset($_POST['decision_notes'])) $decision_notes = trim($_POST['decision_notes']);

        $u2 = $conn->prepare("UPDATE grade_corrections SET status = 'Approved', registrar_id = ?, decision_notes = ?, decision_date = NOW() WHERE request_id = ?");
        $u2->bind_param("isi", $_SESSION['user_id'], $decision_notes, $request_id);
        $u2->execute();

        logAction($conn, $_SESSION['user_id'], "Approved correction request ID $request_id for grade ID $grade_id");

        if ($faculty_for_notify) {
            addNotification($conn, $faculty_for_notify, "Your correction request #$request_id was approved and the grade was unlocked for resubmission.");
        }

        echo "<p style='color:green;'>Correction approved — grade unlocked and returned to faculty.</p>";
    }
}

// Handle reject correction request
if (isset($_POST['reject_correction'])) {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);
    $request_id = intval($_POST['request_id']);

    $chk = $conn->prepare("SELECT status, faculty_id FROM grade_corrections WHERE request_id = ? AND status = 'Pending'");
    $chk->bind_param("i", $request_id);
    $chk->execute();
    $cres = $chk->get_result();
    if ($cres->num_rows === 0) {
        echo "<p style='color:red;'>Invalid or already-processed correction request.</p>";
    } else {
        $crow = $cres->fetch_assoc();
        $faculty_for_notify = $crow['faculty_id'] ?? null;
        $decision_notes = '';
        if (isset($_POST['decision_notes'])) $decision_notes = trim($_POST['decision_notes']);

        $u = $conn->prepare("UPDATE grade_corrections SET status = 'Rejected', registrar_id = ?, decision_notes = ?, decision_date = NOW() WHERE request_id = ?");
        $u->bind_param("isi", $_SESSION['user_id'], $decision_notes, $request_id);
        $u->execute();

        logAction($conn, $_SESSION['user_id'], "Rejected correction request ID $request_id");

        if ($faculty_for_notify) {
            addNotification($conn, $faculty_for_notify, "Your correction request #$request_id was rejected. Notes: $decision_notes");
        }

        echo "<p style='color:red;'>Correction request rejected.</p>";
    }
}
?>

</body>
</html>