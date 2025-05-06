<?php
require '../vendor/autoload.php';
include '../includes/connection.php';

use phpseclib3\Crypt\RSA;

function encryptMessage($receiver_id, $message, $pdo) {
    $stmt = $pdo->prepare("SELECT public_key FROM users WHERE id = ?");
    $stmt->execute([$receiver_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    //Validates presence of keys
    if (!$user || empty($user['public_key'])) {
        die("not found");
    }

    $publicKey = RSA::loadPublicKey($user['public_key']);
    return base64_encode($publicKey->encrypt($message));
}
?>
