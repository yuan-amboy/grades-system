<?php
function convertGrade($percentage) {
    if ($percentage >= 98) return [1.00, "Excellent"];
    if ($percentage >= 95) return [1.25, "Excellent"];
    if ($percentage >= 92) return [1.50, "Very Good"];
    if ($percentage >= 89) return [1.75, "Very Good"];
    if ($percentage >= 86) return [2.00, "Good"];
    if ($percentage >= 83) return [2.25, "Good"];
    if ($percentage >= 80) return [2.50, "Good"];
    if ($percentage >= 77) return [2.75, "Satisfactory"];
    if ($percentage >= 75) return [3.00, "Passed"];
    return [5.00, "Failed"];
}
?>