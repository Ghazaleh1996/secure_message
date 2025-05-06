<?php
session_start();
require '../vendor/autoload.php';
include '../includes/connection.php';

use phpseclib3\Crypt\RSA;

//ensure only logged-in teachers can access
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'teacher') {
    die("unauthorized access");
}

$teacher_id = $_SESSION['user_id'];

//fetch teacher's private key
$stmt = $pdo->prepare("SELECT private_key FROM users WHERE id = ?");
$stmt->execute([$teacher_id]);
$teacher = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$teacher || empty($teacher['private_key'])) {
    die("not found for teacher id" . htmlspecialchars($teacher_id));
}

$privateKey = RSA::loadPrivateKey($teacher['private_key']);

//fetch and decrypt received messages
$stmt = $pdo->prepare("SELECT m.encrypted_message, u.name AS sender_name 
                       FROM messages m 
                       JOIN users u ON m.sender_id = u.id 
                       WHERE m.receiver_id = ?");
$stmt->execute([$teacher_id]);

$messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Received Messages</title>
</head>
<body>
    <h2>Received Secure Messages</h2>
    <ul>
        <?php foreach ($messages as $msg): 
            try {
                $decryptedMessage = $privateKey->decrypt(base64_decode($msg['encrypted_message']));
            } catch (Exception $e) {
                $decryptedMessage = "error";
            }
        ?>
            <li>
                <strong>From: <?php echo htmlspecialchars($msg['sender_name']); ?></strong><br>
                <span><?php echo htmlspecialchars($decryptedMessage); ?></span>
            </li>
        <?php endforeach; ?>
    </ul>
</body>
</html>
