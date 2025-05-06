<?php
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require '../vendor/autoload.php';
require '../includes/connection.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Store session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['name'] = $user['name'];
            $_SESSION['public_key'] = $user['public_key'];
            $_SESSION['password'] = $password; // Store password 
            $_SESSION['email'] = $user['email']; // Store email for consistency

            // Ensure session variables are set
            if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
                session_destroy();
                die("Session failed to set. Please try logging in again.");
            }

            // Redirect user based on role
            if ($user['role'] === 'student') {
                header("Location: ../dashboards/student_dashboard.php");
                exit();
            } elseif ($user['role'] === 'teacher') {
                header("Location: ../dashboards/teacher_dashboard.php");
                exit();
            } else {
                session_destroy();
                die("Invalid role detected: " . htmlspecialchars($user['role']));
            }
        } else {
            echo "<script>alert('Invalid email or password'); window.location.href='login.php';</script>";
            exit();
        }
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h2>Login to Secure Messaging</h2>
    <form action="login.php" method="POST">
        <label for="email">Email:</label>
        <input type="email" name="email" required>

        <label for="password">Password:</label>
        <input type="password" name="password" required>

        <button type="submit">Login</button>
    </form>
</body>
</html>
