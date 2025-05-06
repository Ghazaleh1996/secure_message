<?php
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../includes/connection.php';

use phpseclib3\Crypt\RSA;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $role = $_POST['role'];

    // Check if all required fields are filled
    if (empty($name) || empty($email) || empty($password) || empty($confirm_password) || empty($role)) {
        die("Missing required fields.");
    }

    // Check if passwords match
    if ($password !== $confirm_password) {
        die("Passwords do not match.");
    }

    try {
        // Check if the email already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->rowCount() > 0) {
            die("Email already registered.");
        }

        // Hash the password for secure storage
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Generate RSA Key Pair
        $keyPair = RSA::createKey(2048);
        $privateKey = $keyPair->toString('PKCS8');
        $publicKey = $keyPair->getPublicKey()->toString('PKCS8');

        // Store public key in the database
        $stmt = $pdo->prepare("INSERT INTO users (name, email, password, role, public_key) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$name, $email, $hashed_password, $role, $publicKey]);

        // Get user ID after inserting
        $user_id = $pdo->lastInsertId();
        if (!$user_id) {
            die("Failed to retrieve new user ID.");
        }

        // Define secure encryption parameters
        $encryption_key = hash_pbkdf2("sha256", $password, $email, 100000, 32, true);
        $iv = openssl_random_pseudo_bytes(16);

        // AES encryption of the RSA private key before saving
        $encrypted_private_key = openssl_encrypt($privateKey, 'aes-256-cbc', $encryption_key, 0, $iv);
        if (!$encrypted_private_key) {
            die("Failed to encrypt the private key.");
        }

        // Store IV in database
        $encoded_iv = base64_encode($iv);
        $stmt = $pdo->prepare("UPDATE users SET iv = ? WHERE id = ?");
        $update_success = $stmt->execute([$encoded_iv, $user_id]);

        if (!$update_success) {
            die("Failed to store IV in db");
        }

        // Define storage directory for private keys
        $privateKeyDir = realpath("../keys/private_keys/");
        if (!$privateKeyDir) {
            $privateKeyDir = "../keys/private_keys/";
        }

        // Ensure the directory exists 
        if (!is_dir($privateKeyDir)) {
            if (!mkdir($privateKeyDir, 0700, true)) {
                die("Failed to create directory " . realpath($privateKeyDir));
            }
            echo "directory created: " . realpath($privateKeyDir) . "<br>";
        } else {
            echo "directory exists: " . realpath($privateKeyDir) . "<br>";
        }

        // Store encrypted private key in a file
        $privateKeyPath = $privateKeyDir . "/user_" . $user_id . "_private.enc";
        $write_result = file_put_contents($privateKeyPath, $encrypted_private_key);

        if ($write_result === false) {
            die("Failed to write private key file for User ID $user_id!");
        }

        // Set file permissions after ensuring it was written
        chmod($privateKeyPath, 0600);

        echo "encrypted private key stored successfully for User ID $user_id.<br>";

        // Redirect to login page after successful registration
        echo "<script>alert('registration successful! please log in.'); window.location.href='../auth/login.php';</script>";
        exit();
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
</head>
<body>
    <h2>Register</h2>
    <form action="register.php" method="POST">
        <label for="name">Name:</label>
        <input type="text" name="name" required>

        <label for="email">Email:</label>
        <input type="email" name="email" required>

        <label for="password">Password:</label>
        <input type="password" name="password" required>

        <label for="confirm_password">Confirm Password:</label>
        <input type="password" name="confirm_password" required>

        <label for="role">Role:</label>
        <select name="role" required>
            <option value="student">Student</option>
            <option value="teacher">Teacher</option>
        </select>

        <button type="submit">Register</button>
    </form>
</body>
</html>
