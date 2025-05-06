<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
require '../vendor/autoload.php';
require '../includes/connection.php';

use phpseclib3\Crypt\RSA;

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'teacher') {
    die("Unauthorized access.");
}

$teacher_id = $_SESSION['user_id'];

// Fetch the teacher's email and IV from the database
$stmt = $pdo->prepare("SELECT email, iv FROM users WHERE id = ?");
$stmt->execute([$teacher_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || empty($user['email']) || empty($user['iv'])) {
    die("Error: User not found or missing encryption parameters.");
}

$email = $user['email'];
$iv = base64_decode($user['iv']); // Decode the IV stored in the database

// Check if session has stored password (needed for key generation)
if (!isset($_SESSION['password'])) {
    die("Session password missing. Please log in again.");
}

$password = $_SESSION['password'];

// Define encryption key (must match register.php)
$encryption_key = hash_pbkdf2("sha256", $password, $email, 100000, 32, true);

// Define storage directory for private keys
$privateKeyDir = realpath("../keys/private_keys/");
if (!$privateKeyDir) {
    die("Private key directory not found.");
}

// Define private key path
$privateKeyPath = $privateKeyDir . "/user_" . $teacher_id . "_private.enc";

// Check if private key file exists
if (!file_exists($privateKeyPath)) {
    die("Private key not found for teacher ID " . htmlspecialchars($teacher_id));
}

// Read encrypted private key from file
$encrypted_private_key = file_get_contents($privateKeyPath);

// Decrypt the private key
$privateKey = openssl_decrypt($encrypted_private_key, 'aes-256-cbc', $encryption_key, 0, $iv);
if (!$privateKey) {
    die("Failed to decrypt the private key.");
}

// Load private key into RSA library
try {
    $rsa = RSA::loadPrivateKey($privateKey);
} catch (Exception $e) {
    die("Message could not be decrypted");
}

// Fetch messages for the teacher
$messagesStmt = $pdo->prepare("SELECT m.encrypted_message, u.name AS sender_name 
                               FROM messages m 
                               JOIN users u ON m.sender_id = u.id 
                               WHERE m.receiver_id = ?");
$messagesStmt->execute([$teacher_id]);

$messageCount = $messagesStmt->rowCount();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Teacher Dashboard</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($_SESSION['name']); ?>!</h1>

    <h2>Secure Messages</h2>
    <?php
    if ($messageCount > 0) {
        while ($msg = $messagesStmt->fetch(PDO::FETCH_ASSOC)) {
            try {
                $decryptedMessage = $rsa->decrypt(base64_decode($msg['encrypted_message']));
            } catch (Exception $e) {
                $decryptedMessage = "Error decrypting message: " . $e->getMessage();
            }

            echo "<p><strong>" . htmlspecialchars($msg['sender_name']) . ":</strong> " . htmlspecialchars($decryptedMessage) . "</p>";
        }
    } else {
        echo "<p>No messages received</p>";
    }
    ?>
</body>
</html>
