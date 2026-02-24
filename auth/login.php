<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require "../config/db.php";
require "../includes/audit.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (empty($_POST['csrf_token'])) {
        http_response_code(400);
        die('Missing CSRF token');
    }
    csrf_validate_or_die($_POST['csrf_token']);

    $email = $_POST["email"];
    $pass  = $_POST["password"];

    $stmt = $conn->prepare(
        "SELECT user_id, password_hash, role_id FROM users WHERE email = ?"
    );
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        if (password_verify($pass, $row['password_hash'])) {
            secure_session_regenerate();
            $_SESSION["user_id"] = $row["user_id"];
            $_SESSION["role_id"] = $row["role_id"];

            logAction($conn, $row["user_id"], "User logged in");

            header("Location: ../index.php");
            exit;
        }
    }
    $error = "Invalid credentials";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; }
        .login-box {
            width: 300px;
            margin: 100px auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px #ccc;
        }
        input, button {
            width: 100%;
            padding: 8px;
            margin-top: 10px;
        }
        button {
            background: #2c3e50;
            color: white;
            border: none;
        }
        .error { color: red; text-align:center; }
    </style>
</head>
<body>

<div class="login-box">
    <h3>System Login</h3>

    <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>

    <form method="post">
        <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
        <input type="email" name="email" placeholder="Email" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</div>

</body>
</html>