<?php
session_start();
require '../vendor/autoload.php';
include '../includes/connection.php';

use phpseclib3\Crypt\RSA;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $student_id = $_SESSION['user_id'];
    $teacher_id = $_POST['teacher_id'];
    $message = $_POST['message'];

    //fetch teacher's public key
    $stmt = $pdo->prepare("SELECT public_key FROM users WHERE id = ?");
    $stmt->execute([$teacher_id]);
    $teacher = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$teacher || empty($teacher['public_key'])) {
        die("not found");
    }

    try {
        $publicKey = RSA::loadPublicKey($teacher['public_key']);
        $encryptedMessage = base64_encode($publicKey->encrypt($message));

        //store encrypted message
        $stmt = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, encrypted_message) VALUES (?, ?, ?)");
        $stmt->execute([$student_id, $teacher_id, $encryptedMessage]);

        echo "<script>alert('message sent securely'); window.location.href='../dashboards/student_dashboard.php';</script>";
    } catch (Exception $e) {
        die("failed" . $e->getMessage());
    }
}
?>
