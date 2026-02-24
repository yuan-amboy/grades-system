<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require "../config/db.php";

$errors = [];
$old = ['full_name' => '', 'email' => '', 'role' => 3];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (empty($_POST['csrf_token'])) {
        http_response_code(400);
        die('Missing CSRF token');
    }
    csrf_validate_or_die($_POST['csrf_token']);

    $name  = trim($_POST["full_name"] ?? '');
    $email = trim($_POST["email"] ?? '');
    $pass  = $_POST["password"] ?? '';
    $pass2 = $_POST["confirm_password"] ?? '';
    $role  = intval($_POST["role"] ?? 3);

    $old['full_name'] = $name;
    $old['email'] = $email;
    $old['role'] = $role;

    if ($name === '') $errors[] = 'Full Name is required.';
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid Email is required.';

    // Password policy: min 8 chars, upper, lower, number, special char
    if (strlen($pass) < 8) $errors[] = 'Password must be at least 8 characters.';
    if (!preg_match('/[A-Z]/', $pass)) $errors[] = 'Password must include at least one uppercase letter.';
    if (!preg_match('/[a-z]/', $pass)) $errors[] = 'Password must include at least one lowercase letter.';
    if (!preg_match('/[0-9]/', $pass)) $errors[] = 'Password must include at least one number.';
    if (!preg_match('/[^A-Za-z0-9]/', $pass)) $errors[] = 'Password must include at least one special character.';

    if ($pass !== $pass2) $errors[] = 'Confirm Password does not match.';

    // Check email uniqueness
    if (empty($errors)) {
        $check = $conn->prepare("SELECT COUNT(*) AS cnt FROM users WHERE email = ?");
        $check->bind_param('s', $email);
        $check->execute();
        $res = $check->get_result();
        $row = $res->fetch_assoc();
        if ($row && intval($row['cnt']) > 0) {
            $errors[] = 'Email is already registered.';
        }
    }

    if (empty($errors)) {
        $passwordHash = password_hash($pass, PASSWORD_BCRYPT);

        $stmt = $conn->prepare(
            "INSERT INTO users (full_name, email, password_hash, role_id)
             VALUES (?, ?, ?, ?)"
        );
        $stmt->bind_param("sssi", $name, $email, $passwordHash, $role);
        if ($stmt->execute()) {
            header("Location: login.php");
            exit;
        } else {
            $errors[] = 'Database error while creating account.';
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; }
        .register-box { width: 400px; margin: 50px auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px #ccc; }
        input, select, button { width: 100%; padding: 8px; margin-top: 10px; }
        button { background: #2c3e50; color: white; border: none; }
        .error { color: red; margin-bottom:10px; }
        .success { color: green; }
        .small-link { display:block; margin-top:12px; text-align:center; }
    </style>
</head>
<body>

<div class="register-box">
    <h3>Create Account</h3>

    <?php if (!empty($errors)): ?>
        <div class="error">
            <ul>
            <?php foreach ($errors as $e): ?>
                <li><?php echo htmlspecialchars($e, ENT_QUOTES); ?></li>
            <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="post">
        <?php echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">'; ?>
        <label>Full Name</label>
        <input type="text" name="full_name" value="<?php echo htmlspecialchars($old['full_name'], ENT_QUOTES); ?>" required>

        <label>Email</label>
        <input type="email" name="email" value="<?php echo htmlspecialchars($old['email'], ENT_QUOTES); ?>" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <label>Confirm Password</label>
        <input type="password" name="confirm_password" required>

        <label>Role</label>
        <select name="role">
            <option value="3" <?php echo ($old['role']==3)?'selected':''; ?>>Student</option>
            <option value="1" <?php echo ($old['role']==1)?'selected':''; ?>>Faculty</option>
            <option value="2" <?php echo ($old['role']==2)?'selected':''; ?>>Registrar</option>
        </select>

        <button type="submit">Register</button>
    </form>

    <a class="small-link" href="login.php">Back to Login</a>
</div>

</body>
</html>