<?php
session_start();

// Database connection
$servername = "127.0.0.1";
$username = "root";
$password = "";
$dbname = "remindersystemdb";
$port = 3306;

$conn = new mysqli($servername, $username, $password, $dbname, $port);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get user input
$user = isset($_POST['username']) ? trim($_POST['username']) : '';
$pass = isset($_POST['password']) ? trim($_POST['password']) : '';

// Validate inputs
if (empty($user) || empty($pass)) {
    die("Error: All fields are required!");
}

// Prepare statement to check username
$stmt = $conn->prepare("SELECT id, password FROM user WHERE username = ?");
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    
    // Verify password
    if ($pass === $row['password']) { // Change this to password_hash() later for security
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $user;
        echo "Login successful! Redirecting...";
        header("Location: inject.html"); // Redirect to inject.html
        exit;
    } else {
        echo "<script>alert('Invalid password!'); window.location.href='Index.html';</script>";
        exit;
    }
} else {
    echo "<script>alert('User not found!'); window.location.href='Index.html';</script>";
    exit;
}

$stmt->close();
$conn->close();
?>
