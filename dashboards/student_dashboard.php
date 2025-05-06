<?php
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'student') {
    header("Location: ../auth/login.php");
    exit();
}

require '../vendor/autoload.php';
require '../includes/connection.php';

use phpseclib3\Crypt\RSA;

$student_id = $_SESSION['user_id'];

//handle message sending
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $teacher_id = $_POST['teacher_id'];
    $message = $_POST['message'];

    echo "teacher id:" . htmlspecialchars($teacher_id) . "<br>";
    echo "message:" . htmlspecialchars($message) . "<br>";

    //fetch teacher's public key
    $stmt = $pdo->prepare("SELECT public_key FROM users WHERE id = ?");
    $stmt->execute([$teacher_id]);
    $teacher = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$teacher || empty($teacher['public_key'])) {
        die("teacher not found or public key missing");
    }
    echo "public key: " . htmlspecialchars($teacher['public_key']) . "<br>";

    //encrypt message
    try {
        $publicKey = RSA::loadPublicKey($teacher['public_key']);
        $encryptedMessage = base64_encode($publicKey->encrypt($message));
    } catch (Exception $e) {
        die("encryption failed" . $e->getMessage());
    }

    echo "encrypted message:" . htmlspecialchars($encryptedMessage) . "<br>";

    //store encrypted message in db
    try {
        $stmt = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, encrypted_message) VALUES (?, ?, ?)");
        $stmt->execute([$student_id, $teacher_id, $encryptedMessage]);
        echo "message stored in db successfully.<br>";
    } catch (PDOException $e) {
        die("could not insert message into db. " . $e->getMessage());
    }

    echo "<script>alert('message sent successfully'); window.location.href='student_dashboard.php';</script>";
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Student Dashboard</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($_SESSION['name']); ?>!</h1>

    <h2>Send Secure Message</h2>
    <form action="student_dashboard.php" method="POST">
        <label for="teacher">select teacher:</label>
        <select name="teacher_id" required>
            <?php
            $teachersStmt = $pdo->query("SELECT id, name FROM users WHERE role = 'teacher'");
            while ($teacher = $teachersStmt->fetch(PDO::FETCH_ASSOC)) {
                echo "<option value='" . $teacher['id'] . "'>" . htmlspecialchars($teacher['name']) . "</option>";
            }
            ?>
        </select>
        <textarea name="message" placeholder="enter your message" required></textarea>
        <button type="submit">send secure message</button>
    </form>
</body>
</html>
