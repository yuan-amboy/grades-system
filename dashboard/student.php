<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([3]); // Student only

$student_id = $_SESSION["user_id"];
?>

<!DOCTYPE html>
<html>
<head>
    <title>Student Grade Viewer</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; padding:20px; }
        table { border-collapse: collapse; width: 100%; background:#fff; }
        th, td { border:1px solid #ccc; padding:10px; text-align:center; }
        th { background:#2c3e50; color:#fff; }
        h2 { margin-bottom: 20px; }
    </style>
</head>
<body>

<div style="display:flex; justify-content:space-between; align-items:center;">
    <h2>My Grades</h2>
    <a href="../logout.php" style="background:#c0392b; color:#fff; padding:8px 12px; text-decoration:none; border-radius:4px;">Logout</a>
</div>

<table>
<tr>
    <th>Subject</th>
    <th>Period</th>
    <th>Percentage</th>
    <th>Final Grade</th>
    <th>Remarks</th>
</tr>

<?php
$query = "
SELECT 
    s.subject_code,
    gp.period_name,
    g.percentage,
    g.numeric_grade,
    g.remarks
FROM grades g
JOIN enrollments e ON g.enrollment_id = e.enrollment_id
JOIN subjects s ON e.subject_id = s.subject_id
JOIN grading_periods gp ON g.period_id = gp.period_id
WHERE e.student_id = ?
AND g.status = 'Approved'
ORDER BY s.subject_code, gp.period_id
";

$stmt = $conn->prepare($query);
$stmt->bind_param("i", $student_id);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()):
?>

<tr>
    <td><?= $row["subject_code"] ?></td>
    <td><?= $row["period_name"] ?></td>
    <td><?= $row["percentage"] ?></td>
    <td><?= $row["numeric_grade"] ?></td>
    <td><?= $row["remarks"] ?></td>
</tr>

<?php endwhile; ?>
</table>

</body>
</html>