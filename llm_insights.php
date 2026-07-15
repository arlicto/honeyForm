<?php
require_once 'db.php';

ensure_session_started();
$isAdmin = !empty($_SESSION['is_admin']);

if (!$isAdmin) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden']);
    exit;
}

header('Content-Type: application/json');

$cacheFile = sys_get_temp_dir() . '/honeyform_llm_cache.json';
$statusFile = sys_get_temp_dir() . '/honeyform_llm_status.json';
$force = isset($_GET['force']) && $_GET['force'] == '1';

// Function to get current status
function getLlmStatus() {
    global $statusFile;
    if (file_exists($statusFile)) {
        $statusData = json_decode(file_get_contents($statusFile), true);
        // If it's been processing for more than 2 minutes, assume it failed/timed out
        if (isset($statusData['status']) && $statusData['status'] === 'processing') {
            if (isset($statusData['updated_at']) && (time() - $statusData['updated_at'] > 120)) {
                return 'idle';
            }
            return 'processing';
        }
    }
    return 'idle';
}

$currentStatus = getLlmStatus();

if ($force && $currentStatus !== 'processing') {
    // Trigger worker in background
    $workerPath = __DIR__ . '/llm_worker.php';
    // Use nohup and redirect output to /dev/null to ensure it detaches correctly on Linux
    $cmd = "php " . escapeshellarg($workerPath) . " > /dev/null 2>&1 &";
    exec($cmd);
    
    // Immediately set status to processing so subsequent polls see it
    file_put_contents($statusFile, json_encode(['status' => 'processing', 'updated_at' => time()]));
    
    echo json_encode(['status' => 'processing', 'message' => 'Generation started']);
    exit;
}

// Return status and cached content if available
$response = [
    'status' => $currentStatus,
    'insight' => '',
    'cached' => true
];

if (file_exists($cacheFile)) {
    $cached = @file_get_contents($cacheFile);
    if ($cached) {
        $decoded = json_decode($cached, true);
        if ($decoded) {
            $response['insight'] = $decoded['insight'];
            $response['timestamp'] = $decoded['timestamp'] ?? 0;
        }
    }
}

echo json_encode($response);
exit;

# 1784053120336865078

# 1784139518856247707
