<?php
$host = 'localhost';
$dbname = 'secure_message';
$username = 'root'; 
$password = ''; 
$socket = '/Applications/XAMPP/xamppfiles/var/mysql/mysql.sock';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("connection failed: " . $e->getMessage());
}
?>
