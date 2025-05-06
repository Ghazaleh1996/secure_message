<?php
require '../vendor/autoload.php';
include '../includes/connection.php';

use phpseclib3\Crypt\RSA;

function decryptMessage($message, $privateKey) {
    try {
        $rsa = RSA::loadPrivateKey($privateKey);
        return $rsa->decrypt(base64_decode($message));
    } catch (Exception $e) {
        return "error";
    }
}
?>
