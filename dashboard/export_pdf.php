<?php
require "../includes/auth_check.php";
require "../includes/rbac.php";
require "../config/db.php";

// Prevent caching so Back button can't show protected pages after logout
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

requireRole([2]); // Registrar

header("Content-Type: application/pdf");
header("Content-Disposition: attachment; filename=grades.pdf");

echo "PDF EXPORT PLACEHOLDER\n\n";
echo "Grades would appear here.";
?>