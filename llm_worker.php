<?php
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}
require_once 'db.php';

// This script is intended to be run in the background.
// It does not check for admin session because it's triggered by the server itself.
// However, we should ensure it's not accessible via web if possible, 
// though exec() from llm_insights.php is safe.

$cacheFile = sys_get_temp_dir() . '/honeyform_llm_cache.json';
$statusFile = sys_get_temp_dir() . '/honeyform_llm_status.json';

function setStatus($status) {
    global $statusFile;
    file_put_contents($statusFile, json_encode(['status' => $status, 'updated_at' => time()]));
}

setStatus('processing');

// Fetch last 50 logs (logic from llm_insights.php)
try {
    $stmt = $pdo->query("
        SELECT 
            al.attack_type, 
            al.user_agent, 
            al.attempted_username, 
            al.attempted_password, 
            al.http_method, 
            al.timestamp, 
            it.ip_address, 
            it.country_name 
        FROM attack_logs al 
        LEFT JOIN ip_tracking it ON al.ip_id = it.id 
        ORDER BY al.timestamp DESC 
        LIMIT 50
    ");
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (\PDOException $e) {
    setStatus('idle');
    exit;
}

if (empty($logs)) {
    $output = ['insight' => 'No recent logs available to analyze.', 'timestamp' => time(), 'cached' => false];
    file_put_contents($cacheFile, json_encode($output));
    setStatus('idle');
    exit;
}

$logSummary = "";
foreach ($logs as $log) {
    $time = date('H:i:s', strtotime($log['timestamp']));
    $ip = $log['ip_address'] ?? 'Unknown IP';
    $country = $log['country_name'] ?? 'Unknown Country';
    $logSummary .= "- Time: {$time}, IP: {$ip} ({$country}), Type: {$log['attack_type']}, User: {$log['attempted_username']}, Pass: {$log['attempted_password']}, Agent: {$log['user_agent']}\n";
}

$prompt = "You are an expert cybersecurity analyst. Analyze the following recent web server attack logs. Provide a highly concise and direct executive summary. Use a single header '## Executive Security Summary' followed by 3-4 high-impact bullet points covering: most common attack types, primary targets, and threat origins. CRITICAL: Based on the User-Agents and attack patterns, classify if the activity appears to be automated BOT/SCANNER simulation or manual HUMAN hacker activity. Focus only on the most critical patterns.\n\nLogs:\n" . $logSummary;

$url = 'http://localhost:11434/api/generate';
$data = [
    'model' => 'llama3.2:3b',
    'system' => 'You are an expert cybersecurity analyst. YOU MUST OUTPUT IN ENGLISH ONLY. Provide a highly concise, direct executive summary. Classify activity as BOT or HUMAN based on evidence. No conversational filler. Use Markdown headers and bullet points.',
    'prompt' => $prompt,
    'stream' => false
];

$options = [
    'http' => [
        'header'  => "Content-type: application/json\r\n",
        'method'  => 'POST',
        'content' => json_encode($data),
        'timeout' => 45
    ]
];

$context  = stream_context_create($options);
$result = @file_get_contents($url, false, $context);

if ($result === FALSE) {
    // Optionally log error
    setStatus('idle');
    exit;
}

$response = json_decode($result, true);
$insight = $response['response'] ?? 'Could not generate insight.';
$insight = preg_replace('/<think>.*?<\/think>/s', '', $insight);

$output = ['insight' => trim($insight), 'timestamp' => time(), 'cached' => false];
file_put_contents($cacheFile, json_encode($output));

setStatus('idle');

# 1781201908672464251

# 1782843498866384302
