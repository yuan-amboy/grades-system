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

ob_start();

// Handle POST actions early to enforce server-side logic before rendering
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token'])) { http_response_code(400); die('Missing CSRF token'); }
    csrf_validate_or_die($_POST['csrf_token']);

    // Approve
    if (isset($_POST['approve'])) {
        $request_id   = intval($_POST['request_id'] ?? 0);
        $grade_id     = intval($_POST['grade_id']   ?? 0);
        $faculty_id   = intval($_POST['faculty_id'] ?? 0);
        $decision_notes = trim($_POST['decision_notes'] ?? '');

        $conn->begin_transaction();
        try {
            // Ensure request is still pending (row-level lock)
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
            $dup = $conn->prepare(
                "SELECT COUNT(*) AS c FROM grade_corrections
                 WHERE grade_id = ? AND status IN ('Pending','Approved') AND request_id != ?
                 FOR UPDATE"
            );
            $dup->bind_param('ii', $grade_id, $request_id);
            $dup->execute();
            $dres  = $dup->get_result();
            $count = ($dres && $drow = $dres->fetch_assoc()) ? intval($drow['c']) : 0;
            if ($count > 0) {
                $conn->rollback();
                http_response_code(409);
                logAction($conn, $_SESSION['user_id'], "Blocked approval due to another active request for grade ID $grade_id");
                echo "Cannot approve: another active correction request exists for this grade.";
                exit;
            }

            // Unlock grade for resubmission
            $u1 = $conn->prepare("UPDATE grades SET is_locked = 0, status = 'Returned' WHERE grade_id = ?");
            $u1->bind_param('i', $grade_id);
            $u1->execute();

            // Mark correction Approved
            $u2 = $conn->prepare(
                "UPDATE grade_corrections
                 SET status = 'Approved', registrar_id = ?, decision_notes = ?, decision_date = NOW()
                 WHERE request_id = ?"
            );
            $u2->bind_param('isi', $_SESSION['user_id'], $decision_notes, $request_id);
            $u2->execute();

            logAction($conn, $_SESSION['user_id'], "Approved correction request ID $request_id for grade ID $grade_id");
            addNotification($conn, $faculty_id, "Your correction request #$request_id was approved; grade unlocked for resubmission.");

            $conn->commit();

            header('Location: registrar_corrections.php?msg=approved');
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
        $request_id     = intval($_POST['request_id'] ?? 0);
        $faculty_id     = intval($_POST['faculty_id'] ?? 0);
        $decision_notes = trim($_POST['decision_notes'] ?? '');

        $conn->begin_transaction();
        try {
            // Ensure request is still pending (row-level lock)
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

            $u = $conn->prepare(
                "UPDATE grade_corrections
                 SET status = 'Rejected', registrar_id = ?, decision_notes = ?, decision_date = NOW()
                 WHERE request_id = ?"
            );
            $u->bind_param('isi', $_SESSION['user_id'], $decision_notes, $request_id);
            $u->execute();

            logAction($conn, $_SESSION['user_id'], "Rejected correction request ID $request_id");
            addNotification($conn, $faculty_id, "Your correction request #$request_id was rejected. Notes: $decision_notes");

            $conn->commit();

            header('Location: registrar_corrections.php?msg=rejected');
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            http_response_code(500);
            echo "Server error";
            exit;
        }
    }
}

// ── Fetch only Pending requests ────────────────────────────────────────────
$stmt = $conn->prepare(
    "SELECT
        gc.request_id,
        gc.grade_id,
        gc.status        AS corr_status,
        gc.faculty_id,
        gc.reason,
        u.full_name      AS student,
        s.subject_code,
        gp.period_name,
        g.percentage,
        r.full_name      AS requester
     FROM grade_corrections gc
     JOIN grades g          ON gc.grade_id      = g.grade_id
     JOIN enrollments e     ON g.enrollment_id  = e.enrollment_id
     JOIN users u           ON e.student_id     = u.user_id
     JOIN subjects s        ON e.subject_id     = s.subject_id
     JOIN grading_periods gp ON g.period_id     = gp.period_id
     JOIN users r           ON gc.faculty_id    = r.user_id
     WHERE gc.status = 'Pending'
     ORDER BY gc.request_id ASC"
);
$stmt->execute();
$res = $stmt->get_result();

// Build a clean array — double-verify each row's status from DB to guard
// against stale data or race conditions before rendering action buttons.
$pending_rows = [];
while ($row = $res->fetch_assoc()) {
    // Hard server-side status check (second read)
    $statusChk = $conn->prepare("SELECT status FROM grade_corrections WHERE request_id = ?");
    $statusChk->bind_param('i', $row['request_id']);
    $statusChk->execute();
    $sr = $statusChk->get_result();
    if (!($sr && $srow = $sr->fetch_assoc())) continue;
    if (trim($srow['status']) !== 'Pending') continue;   // skip non-pending

    $pending_rows[] = $row;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Registrar – Pending Correction Requests</title>
    <style>
        body  { font-family: Arial, sans-serif; background: #f4f6f8; padding: 20px; }
        h2    { margin-bottom: 6px; }
        .sub  { color: #555; font-size: .9em; margin-bottom: 16px; }
        table { border-collapse: collapse; width: 100%; background: #fff; }
        th, td{ border: 1px solid #ccc; padding: 10px; text-align: left; vertical-align: middle; }
        th    { background: #34495e; color: #fff; }
        tr:nth-child(even) { background: #f9f9f9; }
        .empty-msg { background:#fff; padding:16px; border:1px solid #ccc; color:#666; }
        input[type=text]  { width: 160px; padding: 5px; }
        button.approve    { background: #27ae60; color: #fff; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; }
        button.reject     { background: #c0392b; color: #fff; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; margin-left: 4px; }
        .flash-approved   { background: #d4edda; color: #155724; padding: 10px; margin-bottom: 12px; border: 1px solid #c3e6cb; border-radius: 4px; }
        .flash-rejected   { background: #f8d7da; color: #721c24; padding: 10px; margin-bottom: 12px; border: 1px solid #f5c6cb; border-radius: 4px; }
        .top-bar          { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
        a.logout          { background: #c0392b; color: #fff; padding: 8px 12px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>

<div class="top-bar">
    <h2>Registrar – Pending Correction Requests</h2>
    <a class="logout" href="../logout.php">Logout</a>
</div>
<p class="sub">Only <strong>Pending</strong> correction requests are shown below. Approved and Rejected requests are not displayed.</p>

<?php
// Flash messages after redirect
if (isset($_GET['msg'])) {
    if ($_GET['msg'] === 'approved') {
        echo '<div class="flash-approved">✅ Correction request approved — grade unlocked and returned to faculty.</div>';
    } elseif ($_GET['msg'] === 'rejected') {
        echo '<div class="flash-rejected">❌ Correction request rejected.</div>';
    }
}
?>

<?php if (empty($pending_rows)): ?>
    <div class="empty-msg">No pending correction requests at this time.</div>
<?php else: ?>
<table>
    <thead>
    <tr>
        <th>Request ID</th>
        <th>Student</th>
        <th>Subject</th>
        <th>Period</th>
        <th>Original&nbsp;%</th>
        <th>Requested By</th>
        <th>Reason</th>
        <th>Decision Notes</th>
        <th>Action</th>
    </tr>
    </thead>
    <tbody>
    <?php foreach ($pending_rows as $row): ?>
    <tr>
        <form method="post">
            <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
            <input type="hidden" name="request_id" value="<?= htmlspecialchars($row['request_id'], ENT_QUOTES) ?>">
            <input type="hidden" name="grade_id"   value="<?= htmlspecialchars($row['grade_id'],   ENT_QUOTES) ?>">
            <input type="hidden" name="faculty_id" value="<?= htmlspecialchars($row['faculty_id'], ENT_QUOTES) ?>">

            <td><?= htmlspecialchars($row['request_id'],  ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['student'],     ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['subject_code'],ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['period_name'], ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['percentage'],  ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['requester'],   ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['reason'],      ENT_QUOTES) ?></td>
            <td><input type="text" name="decision_notes" placeholder="Notes (required)" required></td>
            <td>
                <button type="submit" name="approve" class="approve">Approve</button>
                <button type="submit" name="reject"  class="reject">Reject</button>
            </td>
        </form>
    </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

</body>
</html>
