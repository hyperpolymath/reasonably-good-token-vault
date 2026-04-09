#!/usr/bin/php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault - Asterisk AGI for MFA Verification
//
// This script provides telephone-based MFA verification
// Callers can verify their identity via phone call

// Set headers for AGI
header('Content-Type: text/plain');

// Read AGI environment variables
$agi = array();
while (!feof(STDIN)) {
    $line = fgets(STDIN);
    if (trim($line) == '') break;
    list($key, $value) = explode(': ', trim($line), 2);
    $agi[$key] = trim($value);
}

// Configuration
$apiUrl = getenv('SVALINN_API_URL') ?: 'http://localhost:8443';
$apiKey = getenv('SVALINN_API_KEY');

// Get caller ID
$callerId = $agi['agi_callerid'];

// Clean caller ID (remove non-numeric)
$cleanCallerId = preg_replace('/[^0-9]/', '', $callerId);

// Log call
file_put_contents('php://stderr', "MFA verification call from: $cleanCallerId\n");

// Check if we have API key
if (empty($apiKey)) {
    echo "VERBOSE "Invalid configuration: API key not set" . "\n";
    echo "HANGUP\n";
    exit(1);
}

// Function to make API calls
function makeApiCall($url, $method = 'GET', $data = null, $apiKey) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $apiKey
    ]);
    
    if ($method == 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode >= 200 && $httpCode < 300) {
        return json_decode($response, true);
    } else {
        throw new Exception("API error: HTTP " . $httpCode . " - " . $response);
    }
}

try {
    // Step 1: Find user by phone number
    $users = makeApiCall($apiUrl . '/api/v1/users?phone=' . $cleanCallerId, 'GET', null, $apiKey);
    
    if (empty($users)) {
        echo "STREAM FILE "no-user" "#"\n";
        echo "HANGUP\n";
        exit(0);
    }
    
    // Use first user found
    $user = $users[0];
    
    // Step 2: Prompt for MFA code
    echo "STREAM FILE "enter-mfa-code" "#"\n";
    echo "READ VAR mfa_code 6 10000 #\n";
    
    // Get MFA code from caller
    $mfaCode = trim(fgets(STDIN));
    
    if (empty($mfaCode)) {
        echo "STREAM FILE "no-code-entered" "#"\n";
        echo "HANGUP\n";
        exit(0);
    }
    
    // Step 3: Verify MFA code
    $verifyUrl = $apiUrl . '/api/v1/mfa/verify/' . $user['username'];
    $result = makeApiCall($verifyUrl, 'POST', [
        'code' => $mfaCode,
        'method' => 'totp'
    ], $apiKey);
    
    if ($result['success']) {
        // MFA successful
        echo "STREAM FILE "mfa-success" "#"\n";
        echo "SET VAR mfa_verified 1\n";
        echo "SET VAR mfa_user " . $user['username'] . "\n";
    } else {
        // MFA failed
        echo "STREAM FILE "mfa-failed" "#"\n";
        echo "SET VAR mfa_verified 0\n";
    }
    
} catch (Exception $e) {
    file_put_contents('php://stderr', "Error: " . $e->getMessage() . "\n");
    echo "STREAM FILE "system-error" "#"\n";
    echo "HANGUP\n";
    exit(1);
}

// End call
echo "HANGUP\n";
?>
