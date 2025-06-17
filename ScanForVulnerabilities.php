<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

class ScanForVulnerabilities extends Command
{
    protected $signature = 'scan:vulnerabilities';
    protected $description = 'Scan the Laravel application for common vulnerabilities';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        $this->info('Starting vulnerability scan...');
        
        // Step 1: Fetch all routes
        $routes = \Illuminate\Support\Facades\Artisan::call('route:list');
        
        // Step 2: Perform vulnerability checks for each route
        $vulnerabilities = [];
        foreach ($routes as $route) {
            $url = $this->getUrlFromRoute($route);
            
            // Check for SQL injection
            if ($this->checkSqlInjection($url)) {
                $vulnerabilities[] = [
                    'url' => $url,
                    'type' => 'SQL Injection',
                    'recommendation' => 'Ensure that inputs are properly sanitized using parameterized queries or query builders.'
                ];
            }

            // You can add more checks like XSS, CSRF, etc. here...
        }

        // Step 3: Generate a report
        $this->info('Vulnerability scan completed.');
        $this->line($this->generateReport($vulnerabilities));
    }

    private function getUrlFromRoute($route)
    {
        // Example: Convert route to a URL (basic conversion)
        return url($route['uri']);
    }

    private function checkSqlInjection($url)
    {
        // Simple SQL Injection detection (this should be enhanced)
        $patterns = [
            "/(\%27)|(\')|(\-\-)|(\%23)|(#)/i",
            "/(select|union|insert|drop|update|delete)/i"
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $url)) {
                return true;
            }
        }
        return false;
    }

    private function generateReport($vulnerabilities)
    {
        $report = '';
        foreach ($vulnerabilities as $vulnerability) {
            $report .= "URL: {$vulnerability['url']}\n";
            $report .= "Vulnerability Type: {$vulnerability['type']}\n";
            $report .= "Recommendation: {$vulnerability['recommendation']}\n\n";
        }
        return $report;
    }
}
