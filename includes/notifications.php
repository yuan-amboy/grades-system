<?php
require_once __DIR__ . '/session.php';

function addNotification($conn, $user_id, $message, $type = null) {
    // Insert minimal fields; rely on DB defaults for timestamps and unread flag
    $stmt = $conn->prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)");
    $stmt->bind_param("is", $user_id, $message);
    $stmt->execute();
}

function getNotifications($conn, $user_id, $limit = 50) {
    $stmt = $conn->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY notification_id DESC LIMIT ?");
    $stmt->bind_param("ii", $user_id, $limit);
    $stmt->execute();
    return $stmt->get_result();
}

function getUnreadCount($conn, $user_id) {
    // If notifications table has an 'is_read' column this will count unread, otherwise returns total
    $stmt = $conn->prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND (is_read IS NULL OR is_read = 0)");
    if ($stmt) {
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) return intval($row['c']);
        return 0;
    }
    // Fallback: count all notifications for user
    $stmt2 = $conn->prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = ?");
    $stmt2->bind_param('i', $user_id);
    $stmt2->execute();
    $r2 = $stmt2->get_result();
    if ($row2 = $r2->fetch_assoc()) return intval($row2['c']);
    return 0;
}

function markNotificationRead($conn, $notification_id) {
    $stmt = $conn->prepare("UPDATE notifications SET is_read = 1 WHERE notification_id = ?");
    $stmt->bind_param("i", $notification_id);
    $stmt->execute();
}

?>