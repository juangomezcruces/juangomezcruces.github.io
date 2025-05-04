<?php
// Enable strict error reporting
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// 1. CSRF Protection
session_start();
if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    http_response_code(403);
    die("Security error: Invalid CSRF token");
}

// 2. Honeypot Trap
if (!empty($_POST['website'])) {
    http_response_code(200); // Fake success for bots
    exit;
}

// 3. Input Validation
$required_fields = ['name', 'email', 'subject', 'message'];
foreach ($required_fields as $field) {
    if (empty($_POST[$field])) {
        http_response_code(400);
        die("Please fill all required fields");
    }
}

// 4. Sanitization
$name = filter_var($_POST['name'], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
$subject = filter_var($_POST['subject'], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);
$message = filter_var($_POST['message'], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);

// 5. Email Validation
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    die("Please enter a valid email address");
}

// 6. Email Headers
$to = "juan.gomezcruces@hpi.de";
$headers = "From: $name <$email>\r\n";
$headers .= "Reply-To: $email\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// 7. Email Content
$email_content = "Name: $name\n";
$email_content .= "Email: $email\n\n";
$email_content .= "Message:\n$message";

// 8. Rate Limiting (simple version)
$ip = $_SERVER['REMOTE_ADDR'];
$cache_file = sys_get_temp_dir() . '/contact_form_' . md5($ip);
if (file_exists($cache_file) && time() - filemtime($cache_file) < 300) {
    http_response_code(429);
    die("Please wait 5 minutes before sending another message");
}

// 9. Send Email
if (mail($to, $subject, $email_content, $headers)) {
    file_put_contents($cache_file, time());
    http_response_code(200);
    echo "Thank you! Your message has been sent.";
} else {
    http_response_code(500);
    echo "Oops! Something went wrong.";
}
?>
