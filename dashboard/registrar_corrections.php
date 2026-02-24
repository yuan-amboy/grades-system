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

requireRole([2]); // Registrar

// Buffer output so we can perform POST-redirect-GET safely from this script
ob_start();

// Handle POST actions early to enforce server-side logic before rendering
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    // Approve
    if (isset($_POST['approve'])) {
        $request_id = intval($_POST['request_id'] ?? 0);
        $grade_id = intval($_POST['grade_id'] ?? 0);
        $faculty_id = intval($_POST['faculty_id'] ?? 0);
        $decision_notes = trim($_POST['decision_notes'] ?? '');

        // Transactional integrity checks
        $conn->begin_transaction();
        try {
            // Ensure request is still pending
            $rchk = $conn->prepare("SELECT status FROM grade_corrections WHERE request_id = ? FOR UPDATE");
            $rchk->bind_param('i', $request_id);
            $rchk->execute();
            $rr = $rchk->get_result();
            if (!($rr && $rrow = $rr->fetch_assoc()) || $rrow['status'] !== 'Pending') {
                $conn->rollback();
                http_response_code(409);
                echo "This request has already been processed.";
                exit;
            }

            // Re-check grade is still locked
            $gchk = $conn->prepare("SELECT is_locked FROM grades WHERE grade_id = ? FOR UPDATE");
            $gchk->bind_param('i', $grade_id);
            $gchk->execute();
            $gr = $gchk->get_result();
            if (!($gr && $grow = $gr->fetch_assoc()) || intval($grow['is_locked']) !== 1) {
                $conn->rollback();
                http_response_code(409);
                echo "Cannot approve: grade is not locked.";
                exit;
            }

            // Ensure no other active request exists for this grade
            $dup = $conn->prepare("SELECT COUNT(*) AS c FROM grade_corrections WHERE grade_id = ? AND status IN ('Pending','Approved') AND request_id != ? FOR UPDATE");
            $dup->bind_param('ii', $grade_id, $request_id);
            $dup->execute();
            $dres = $dup->get_result();
            $count = ($dres && $drow = $dres->fetch_assoc()) ? intval($drow['c']) : 0;
            if ($count > 0) {
                $conn->rollback();
                http_response_code(409);
                logAction($conn, $_SESSION['user_id'], "Blocked approval due to another active request for grade ID $grade_id");
                echo "Cannot approve: another active correction request exists for this grade.";
                exit;
            }

            // Unlock the grade for resubmission
            $u1 = $conn->prepare("UPDATE grades SET is_locked = 0, status = 'Returned' WHERE grade_id = ?");
            $u1->bind_param('i', $grade_id);
            $u1->execute();

            // Update correction record
            $u2 = $conn->prepare("UPDATE grade_corrections SET status = 'Approved', registrar_id = ?, decision_notes = ?, decision_date = NOW() WHERE request_id = ?");
            $u2->bind_param('isi', $_SESSION['user_id'], $decision_notes, $request_id);
            $u2->execute();

            logAction($conn, $_SESSION['user_id'], "Approved correction request ID $request_id for grade ID $grade_id");

            addNotification($conn, $faculty_id, "Your correction request #$request_id was approved; grade unlocked for resubmission.");

            $conn->commit();

            header('Location: registrar_corrections.php');
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            http_response_code(500);
            echo "Server error";
            exit;
        }
    }

    // Reject
    if (isset($_POST['reject'])) {
        $request_id = intval($_POST['request_id'] ?? 0);
        $faculty_id = intval($_POST['faculty_id'] ?? 0);
        $decision_notes = trim($_POST['decision_notes'] ?? '');

        $conn->begin_transaction();
        try {
            // Ensure request is still pending
            $rchk = $conn->prepare("SELECT status FROM grade_corrections WHERE request_id = ? FOR UPDATE");
            $rchk->bind_param('i', $request_id);
            $rchk->execute();
            $rr = $rchk->get_result();
            if (!($rr && $rrow = $rr->fetch_assoc()) || $rrow['status'] !== 'Pending') {
                $conn->rollback();
                http_response_code(409);
                echo "This request has already been processed.";
                exit;
            }

            $u = $conn->prepare("UPDATE grade_corrections SET status = 'Rejected', registrar_id = ?, decision_notes = ?, decision_date = NOW() WHERE request_id = ?");
            $u->bind_param('isi', $_SESSION['user_id'], $decision_notes, $request_id);
            $u->execute();

            logAction($conn, $_SESSION['user_id'], "Rejected correction request ID $request_id");

            addNotification($conn, $faculty_id, "Your correction request #$request_id was rejected. Notes: $decision_notes");

            $conn->commit();

            header('Location: registrar_corrections.php');
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            http_response_code(500);
            echo "Server error";
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Registrar - Correction Requests</title>
    <style>table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:8px;text-align:left}</style>
</head>
<body>
<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>Pending Correction Requests</h2>
    <a href="../logout.php">Logout</a>
</div>

<table>
<tr>
    <th>Request ID</th>
    <th>Student</th>
    <th>Subject</th>
    <th>Period</th>
    <th>Original %</th>
    <th>Requested By</th>
    <th>Reason</th>
    <th>Decision Notes</th>
    <th>Action</th>
</tr>

<?php
$stmt = $conn->prepare(
    "SELECT gc.request_id, gc.grade_id, gc.status AS corr_status, u.full_name AS student, s.subject_code, gp.period_name, g.percentage, r.full_name AS requester, gc.reason, gc.faculty_id
     FROM grade_corrections gc
     JOIN grades g ON gc.grade_id = g.grade_id
     JOIN enrollments e ON g.enrollment_id = e.enrollment_id
     JOIN users u ON e.student_id = u.user_id
     JOIN subjects s ON e.subject_id = s.subject_id
     JOIN grading_periods gp ON g.period_id = gp.period_id
     JOIN users r ON gc.faculty_id = r.user_id
     WHERE gc.status = ?"
);
$status_filter = 'Pending';
$stmt->bind_param('s', $status_filter);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()):
    // double-check server-side status sanity
    if (trim($row['corr_status']) !== 'Pending') continue;

    // Re-verify status from DB to protect against races or stale data before rendering actions
    $statusChk = $conn->prepare("SELECT status FROM grade_corrections WHERE request_id = ?");
    $statusChk->bind_param('i', $row['request_id']);
    $statusChk->execute();
    $sr = $statusChk->get_result();
    if (!($sr && $srow = $sr->fetch_assoc())) continue;
    if (trim($srow['status']) !== 'Pending') continue;
?>
<tr>
<form method="post">
    <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
    <td><?= htmlspecialchars($row['request_id'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['student'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['subject_code'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['period_name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['percentage'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['requester'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['reason'], ENT_QUOTES) ?></td>
    <td><input type="text" name="decision_notes" placeholder="Notes (required)" required></td>
    <td>
        <input type="hidden" name="request_id" value="<?= htmlspecialchars($row['request_id'], ENT_QUOTES) ?>">
        <input type="hidden" name="grade_id" value="<?= htmlspecialchars($row['grade_id'], ENT_QUOTES) ?>">
        <input type="hidden" name="faculty_id" value="<?= htmlspecialchars($row['faculty_id'], ENT_QUOTES) ?>">
        <button type="submit" name="approve" style="background:#27ae60;color:#fff">Approve</button>
        <button type="submit" name="reject" style="background:#c0392b;color:#fff">Reject</button>
    </td>
</form>
</tr>
<?php endwhile; ?>
</table>

</body>
</html>