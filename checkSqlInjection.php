<?php
function checkSqlInjection($url) {
    $patterns = [
        "/(\%27)|(\')|(\-\-)|(\%23)|(#)/i",  // Basic SQL injection patterns
        "/(select|union|insert|drop|update|delete)/i"  // SQL keywords
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $url)) {
            return true;  // Potential SQL Injection vulnerability
        }
    }
    return false;
}
