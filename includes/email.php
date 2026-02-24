<?php
function sendEmail($to, $subject, $message) {
    @mail($to, $subject, $message);
}
?>