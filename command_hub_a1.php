<?php
require_once 'db.php';

session_start();
$isAdmin = !empty($_SESSION['is_admin']);

// Fetch last-updated timestamp from attack_logs to avoid showing a misleading static time
$lastUpdatedDisplay = null;
try {
    $stmtLast = $pdo->query("SELECT MAX(timestamp) FROM attack_logs");
    $last = $stmtLast->fetchColumn();
    $lastUpdatedDisplay = $last ? date('Y-m-d H:i:s', strtotime($last)) . ' UTC' : gmdate('Y-m-d H:i:s') . ' UTC';
} catch (\PDOException $e) {
    $lastUpdatedDisplay = gmdate('Y-m-d H:i:s') . ' UTC';
}

// --- PATH TRAVERSAL / ATTACK TRAP ---
// Only run the trap logic for unauthenticated visitors to avoid self-trapping admins
if (!$isAdmin) {
$requestUri = $_SERVER['REQUEST_URI'] ?? '';
$queryString = $_SERVER['QUERY_STRING'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'];
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

$detected = detect_attack_type([
    'user_agent' => $userAgent,
    'request_uri' => $requestUri,
    'params' => $_GET,
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET'
]);

if ($detected !== 'Brute Force') {
    $attackType = $detected;
    $method = $_SERVER['REQUEST_METHOD'];
    $geo = getGeoLocation($ip);
    $payload = json_encode(['uri' => $requestUri, 'GET_params' => $_GET]);
    
    try {
        $stmtIP = $pdo->prepare("INSERT INTO ip_tracking (ip_address, country_code, country_name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE total_attacks = total_attacks + 1, country_code = VALUES(country_code), country_name = VALUES(country_name)");
        $stmtIP->execute([$ip, $geo['country_code'], $geo['country_name']]);
        
        $stmtGetIP = $pdo->prepare("SELECT id FROM ip_tracking WHERE ip_address = ?");
        $stmtGetIP->execute([$ip]);
        $ip_id = $stmtGetIP->fetchColumn();

        $stmt = $pdo->prepare("INSERT INTO attack_logs (ip_id, user_agent, attempted_username, attempted_password, attack_type, http_method, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$ip_id, $userAgent, '', '', $attackType, $method, $payload]);
    } catch (\PDOException $e) {
        // Silently fail for the honeypot
    }
    
    // Serve a fake 403 Forbidden page to stop the attacker from seeing the dashboard
    http_response_code(403);
    die("<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p>");
}
// --- END TRAP ---

}

// For unauthenticated users who were not trapped above, hide the page
if (!$isAdmin) {
    http_response_code(404);
    echo 'Not Found';
    exit;
}

// Admin session already started above and verified for access control

// 1. Total attacks
$stmtTotal = $pdo->query("SELECT COUNT(*) FROM attack_logs");
$totalAttacks = $stmtTotal->fetchColumn() ?: 0;

// 2. Unique IPs
$stmtIPs = $pdo->query("SELECT COUNT(*) FROM ip_tracking");
$uniqueIPs = $stmtIPs->fetchColumn() ?: 0;

// 3. Most targeted username
$stmtUser = $pdo->query("SELECT attempted_username, COUNT(*) as c FROM attack_logs GROUP BY attempted_username ORDER BY c DESC LIMIT 1");
$topUserResult = $stmtUser->fetch();
$mostTargetedUsername = $topUserResult ? $topUserResult['attempted_username'] : 'N/A';

// 4. Attack types percentages (via shared stats helpers)
$attackTypePercents = stats_get_attack_type_percentages($pdo);
$attackTypes = stats_get_attack_type_counts($pdo);

$sqliCount = $attackTypes['SQLi'] ?? 0;
$bruteForceCount = $attackTypes['Brute Force'] ?? 0;
$pathTraversalCount = $attackTypes['Path Traversal'] ?? 0;

$sqliPercent = $attackTypePercents['SQLi'] ?? 0;
$bruteForcePercent = $attackTypePercents['Brute Force'] ?? 0;
$pathTraversalPercent = $attackTypePercents['Path Traversal'] ?? 0;

// 5. Pen-test Tools Detection
$stmtSqlmap = $pdo->query("SELECT COUNT(*) FROM attack_logs WHERE LOWER(user_agent) LIKE '%sqlmap%'");
$sqlmapCount = $stmtSqlmap->fetchColumn() ?: 0;

$stmtNikto = $pdo->query("SELECT COUNT(*) FROM attack_logs WHERE LOWER(user_agent) LIKE '%nikto%'");
$niktoCount = $stmtNikto->fetchColumn() ?: 0;

$stmtHydra = $pdo->query("SELECT COUNT(*) FROM attack_logs WHERE LOWER(user_agent) LIKE '%hydra%'");
$hydraCount = $stmtHydra->fetchColumn() ?: 0;

$stmtCurl = $pdo->query("SELECT COUNT(*) FROM attack_logs WHERE LOWER(user_agent) LIKE '%curl%'");
$curlCount = $stmtCurl->fetchColumn() ?: 0;

// 6. Top 10 IPs (via shared stats helpers)
$topIPs = stats_get_top_ips($pdo, 10);

// 7. Top 10 Usernames
$stmtTopUsers = $pdo->query("SELECT attempted_username, COUNT(*) as c FROM attack_logs WHERE attempted_username != '' GROUP BY attempted_username ORDER BY c DESC LIMIT 10");
$topUsersList = $stmtTopUsers->fetchAll();

// 8. Top 10 Passwords
$stmtTopPass = $pdo->query("SELECT attempted_password, COUNT(*) as c FROM attack_logs WHERE attempted_password != '' GROUP BY attempted_password ORDER BY c DESC LIMIT 10");
$topPasswords = $stmtTopPass->fetchAll();

// 9. Time-Series Data (Hourly — last 48 hours)
// Limit the chart to a recent window to keep visualizations fast and readable as data grows
$hoursWindow = 48; // change to 24 for last 24 hours
$endDt = new DateTime();
$endDt->setTime((int)$endDt->format('H'), 0, 0); // align to hour
$startDt = (clone $endDt)->modify('-' . ($hoursWindow - 1) . ' hours');

$stmtChart = $pdo->prepare("SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00') as hr, COUNT(*) as c FROM attack_logs WHERE timestamp >= ? GROUP BY hr ORDER BY hr ASC");
$stmtChart->execute([$startDt->format('Y-m-d H:i:s')]);
$chartMap = $stmtChart->fetchAll(PDO::FETCH_KEY_PAIR); // hr => count

$chartLabels = [];
$chartData = [];
$current = clone $startDt;
for ($i = 0; $i < $hoursWindow; $i++) {
    $slotKey = $current->format('Y-m-d H:00');
    $chartLabels[] = $current->format('m-d H:00');
    $chartData[] = (int)($chartMap[$slotKey] ?? 0);
    $current->modify('+1 hour');
}
$chartLabelsJson = json_encode($chartLabels);
$chartDataJson = json_encode($chartData);

// 10. Top Countries
$stmtCountries = $pdo->query("SELECT country_code, country_name, SUM(total_attacks) as c FROM ip_tracking WHERE country_code IS NOT NULL AND country_code != 'XX' GROUP BY country_code, country_name ORDER BY c DESC LIMIT 5");
$topCountries = $stmtCountries->fetchAll();

function getFlagEmoji($code) {
    if (!$code || $code === 'XX') return '🌍';
    return (string) preg_replace_callback('/./', static fn (array $m) => mb_chr(ord($m[0]) + 127397, 'UTF-8'), strtoupper($code));
}

// 11. Day x Hour Heatmap Data
$stmtHeatmap = $pdo->query("
    SELECT DAYOFWEEK(timestamp) as d, HOUR(timestamp) as h, COUNT(*) as c 
    FROM attack_logs 
    GROUP BY d, h
");
$heatmapRaw = $stmtHeatmap->fetchAll();

// Initialize 7x24 grid with 0
$heatmapData = array_fill(1, 7, array_fill(0, 24, 0));
$maxHeat = 0;
foreach ($heatmapRaw as $row) {
    $d = (int)$row['d']; // 1 = Sunday, 7 = Saturday
    $h = (int)$row['h'];
    $c = (int)$row['c'];
    $heatmapData[$d][$h] = $c;
    if ($c > $maxHeat) $maxHeat = $c;
}

$daysOfWeek = [1 => 'Sun', 2 => 'Mon', 3 => 'Tue', 4 => 'Wed', 5 => 'Thu', 6 => 'Fri', 7 => 'Sat'];
?>
<!DOCTYPE html>

<html class="light" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<meta http-equiv="refresh" content="10"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script id="tailwind-config">
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            "colors": {
                    "on-primary-container": "#f7feff",
                    "on-secondary-container": "#5d6466",
                    "secondary-container": "#dae1e3",
                    "surface-dim": "#d6dbdc",
                    "error": "#ba1a1a",
                    "surface-variant": "#dee3e4",
                    "secondary-fixed": "#dde4e6",
                    "on-primary-fixed-variant": "#004f58",
                    "on-primary": "#ffffff",
                    "background": "#f5fafb",
                    "surface-container-low": "#f0f4f5",
                    "primary-fixed": "#97f0ff",
                    "surface-bright": "#f5fafb",
                    "inverse-surface": "#2c3132",
                    "surface-container-high": "#e4e9ea",
                    "on-background": "#171c1d",
                    "on-tertiary-container": "#fffbff",
                    "on-secondary-fixed-variant": "#41484a",
                    "outline-variant": "#bcc9cb",
                    "on-tertiary-fixed-variant": "#703700",
                    "error-container": "#ffdad6",
                    "on-tertiary": "#ffffff",
                    "surface": "#f5fafb",
                    "secondary": "#586062",
                    "primary-container": "#00818f",
                    "on-surface-variant": "#3d494b",
                    "tertiary": "#8d4a0c",
                    "on-tertiary-fixed": "#301400",
                    "surface-container": "#eaeff0",
                    "on-error": "#ffffff",
                    "on-primary-fixed": "#001f24",
                    "on-secondary": "#ffffff",
                    "primary-fixed-dim": "#66d6e7",
                    "on-surface": "#171c1d",
                    "surface-container-highest": "#dee3e4",
                    "on-secondary-fixed": "#161d1f",
                    "tertiary-fixed": "#ffdcc5",
                    "outline": "#6d797b",
                    "secondary-fixed-dim": "#c1c8ca",
                    "tertiary-fixed-dim": "#ffb782",
                    "inverse-on-surface": "#edf2f2",
                    "tertiary-container": "#ab6225",
                    "primary": "#006671",
                    "surface-tint": "#006874",
                    "surface-container-lowest": "#ffffff",
                    "inverse-primary": "#66d6e7",
                    "on-error-container": "#93000a"
            },
            "borderRadius": {
                    "DEFAULT": "0.25rem",
                    "lg": "0.5rem",
                    "xl": "0.75rem",
                    "full": "9999px"
            },
            "spacing": {
                    "xl": "64px",
                    "md": "24px",
                    "lg": "40px",
                    "sm": "16px",
                    "base": "4px",
                    "xs": "8px"
            },
            "fontFamily": {
                    "body-base": ["Inter"],
                    "display": ["Inter"],
                    "label-caps": ["Inter"],
                    "headline-md": ["Inter"],
                    "data-mono": ["JetBrains Mono"]
            },
            "fontSize": {
                    "body-base": ["15px", {"lineHeight": "1.6", "letterSpacing": "0", "fontWeight": "400"}],
                    "display": ["32px", {"lineHeight": "1.2", "letterSpacing": "-0.02em", "fontWeight": "600"}],
                    "label-caps": ["11px", {"lineHeight": "1", "letterSpacing": "0.05em", "fontWeight": "700"}],
                    "headline-md": ["20px", {"lineHeight": "1.4", "letterSpacing": "-0.01em", "fontWeight": "500"}],
                    "data-mono": ["13px", {"lineHeight": "1.5", "letterSpacing": "0", "fontWeight": "450"}]
            }
          }
        }
      }
    </script>
<style>
        .glass-card {
            background: rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid #E2E8F0;
            border-radius: 10px;
            padding: 24px;
        }
        .status-pill {
            border-radius: 4px;
            padding: 2px 8px;
            font-family: 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
    </style>
</head>
<body class="bg-background text-on-surface font-body-base min-h-screen">
<!-- Top Navigation Bar -->
<header class="flex justify-between items-center px-lg py-sm w-full sticky top-0 z-50 bg-surface/70 backdrop-blur-xl border-b border-outline-variant/30 shadow-sm">
<div class="flex items-center gap-md">
<span class="font-display text-headline-md font-bold text-on-surface">Honeyform</span>
<nav class="hidden md:flex items-center space-x-md ml-lg">
<a class="text-primary border-b-2 border-primary font-bold pb-2" href="command_hub_a1.php">Dashboard</a>
<a class="text-on-surface-variant font-medium pb-2 hover:text-primary transition-colors duration-200" href="stream_analyzer.php">Logs</a>
</nav>
</div>
<div class="flex items-center gap-sm">
<div class="hidden md:block relative">
<form method="GET" action="stream_analyzer.php" class="flex items-center">
    <input name="ip" class="bg-surface-container-low border border-outline-variant/50 rounded-lg px-md py-xs text-body-base focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all w-64" placeholder="Search forensic data..." type="text" value="" />
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>" />
    <button type="submit" class="material-symbols-outlined absolute right-2 top-2 text-on-surface-variant">search</button>
</form>
</div>
</div>
</header>
<main class="px-lg py-lg max-w-[1600px] mx-auto">
<!-- Key Metrics Section -->
<section class="grid grid-cols-1 md:grid-cols-2 gap-md mb-xl lg:grid-cols-3">
<div class="glass-card shadow-sm group">
<p class="font-label-caps text-label-caps text-on-surface-variant mb-xs">TOTAL LOGIN ATTEMPTS</p>
<div class="flex items-baseline gap-xs">
<h2 class="font-display text-display text-primary"><?= number_format($totalAttacks) ?></h2>
<span class="text-error font-bold text-xs flex items-center">
<span class="material-symbols-outlined text-sm">trending_up</span>
                        Active
                    </span>
</div>
<p class="text-[12px] text-outline mt-base">Since deployment</p>
</div>
<div class="glass-card shadow-sm">
<p class="font-label-caps text-label-caps text-on-surface-variant mb-xs">UNIQUE IP ADDRESSES</p>
<div class="flex items-baseline gap-xs">
<h2 class="font-display text-display text-on-surface"><?= number_format($uniqueIPs) ?></h2>
</div>
<p class="text-[12px] text-outline mt-base">Global distribution</p>
</div>
<div class="glass-card shadow-sm">
<p class="font-label-caps text-label-caps text-on-surface-variant mb-xs">MOST TARGETED USERNAME</p>
<div class="flex items-baseline gap-xs">
<h2 class="font-display text-display text-on-surface"><?= htmlspecialchars($mostTargetedUsername) ?></h2>
</div>
<p class="text-[12px] text-outline mt-base">Primary attack vector</p>
</div>
</section>
<!-- Main Content Area: Asymmetric Layout -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-lg">
<!-- Left Column: Visualizations & Tools -->
<div class="lg:col-span-8 flex flex-col gap-lg">
<!-- Time-series Chart Section -->
<div class="glass-card flex flex-col gap-md h-[450px]">
<div class="flex justify-between items-center">
<div>
<h3 class="font-headline-md text-headline-md text-on-surface">Login Attempts Over Time</h3>
<p class="text-body-base text-on-surface-variant">Real-time forensic telemetry data</p>
</div>
<div class="flex bg-surface-container rounded-lg p-base">
<button class="px-md py-xs text-label-caps font-bold bg-white shadow-sm rounded-lg text-primary">HOURLY</button>
<button class="px-md py-xs text-label-caps font-bold text-on-surface-variant hover:text-on-surface">DAILY</button>
</div>
</div>
<div class="flex-grow relative w-full h-full min-h-[300px]">
<canvas id="attacksChart" class="w-full h-full"></canvas>
</div>
<script>
document.addEventListener("DOMContentLoaded", function() {
    const ctx = document.getElementById('attacksChart').getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(0, 102, 113, 0.3)'); 
    gradient.addColorStop(1, 'rgba(0, 102, 113, 0.0)');
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: <?= $chartLabelsJson ?>,
            datasets: [{
                label: 'Login Attempts',
                data: <?= $chartDataJson ?>,
                borderColor: '#006671',
                backgroundColor: gradient,
                borderWidth: 2,
                pointBackgroundColor: '#006671',
                pointRadius: 3,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.05)' },
                    ticks: { color: '#6d797b' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#6d797b' }
                }
            }
        }
    });
});
</script>
</div>
<!-- Intelligence & Tooling Badges -->
<div class="grid grid-cols-1 md:grid-cols-2 gap-md">
<div class="glass-card">
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">DETECTED PEN-TEST TOOLS</h4>
<div class="flex flex-wrap gap-sm">
<div class="flex items-center gap-xs px-md py-xs bg-error-container/20 border border-error/20 rounded-lg">
<span class="font-data-mono text-data-mono text-error font-bold">sqlmap</span>
<span class="text-xs bg-error/10 text-error px-xs rounded"><?= number_format($sqlmapCount) ?></span>
</div>
<div class="flex items-center gap-xs px-md py-xs bg-primary-container/10 border border-primary/20 rounded-lg">
<span class="font-data-mono text-data-mono text-primary font-bold">nikto</span>
<span class="text-xs bg-primary/10 text-primary px-xs rounded"><?= number_format($niktoCount) ?></span>
</div>
<div class="flex items-center gap-xs px-md py-xs bg-primary-container/10 border border-primary/20 rounded-lg">
<span class="font-data-mono text-data-mono text-primary font-bold">hydra</span>
<span class="text-xs bg-primary/10 text-primary px-xs rounded"><?= number_format($hydraCount) ?></span>
</div>
<div class="flex items-center gap-xs px-md py-xs bg-surface-container-highest border border-outline-variant/30 rounded-lg">
<span class="font-data-mono text-data-mono text-on-surface-variant">curl</span>
<span class="text-xs bg-outline-variant/20 text-on-surface-variant px-xs rounded"><?= number_format($curlCount) ?></span>
</div>
</div>
</div>
<div class="glass-card">
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">GEOLOCATION SUMMARY</h4>
<div class="space-y-sm">
<?php if (empty($topCountries)): ?>
<p class="text-on-surface-variant text-sm">No geolocation data available.</p>
<?php else: ?>
<?php 
$totalGeoAttacks = array_sum(array_column($topCountries, 'c'));
foreach ($topCountries as $index => $countryRow): 
    $pct = $totalGeoAttacks > 0 ? round(($countryRow['c'] / $totalGeoAttacks) * 100) : 0;
    $barColor = $index === 0 ? 'bg-primary' : 'bg-on-surface-variant';
    $textColor = $index === 0 ? 'text-primary' : 'text-on-surface-variant';
?>
<div class="flex justify-between items-center">
<div class="flex items-center gap-xs">
<span class="text-xs"><?= getFlagEmoji($countryRow['country_code']) ?></span>
<span class="text-body-base"><?= htmlspecialchars($countryRow['country_name']) ?></span>
</div>
<span class="font-data-mono text-data-mono <?= $textColor ?>"><?= $pct ?>%</span>
</div>
<div class="w-full bg-surface-container rounded-full h-1.5 overflow-hidden">
<div class="<?= $barColor ?> h-full" style="width: <?= $pct ?>%"></div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
</div>
</div>
</div>
<!-- Right Column: Top 10 Forensic Lists -->
<aside class="lg:col-span-4 flex flex-col gap-lg">
<div class="glass-card h-full flex flex-col gap-lg">
<!-- Top IPs -->
<div>
<div class="flex justify-between items-end mb-md">
<h4 class="font-headline-md text-headline-md text-on-surface">Top IPs</h4>
<a href="stream_analyzer.php" class="text-primary font-label-caps text-label-caps hover:underline">VIEW LOGS</a>
</div>
<div class="space-y-sm">
<?php if (empty($topIPs)): ?>
<p class="text-on-surface-variant text-sm">No IP data available.</p>
<?php else: ?>
<?php 
$maxIPCount = $topIPs[0]['c']; 
foreach ($topIPs as $ipRow): 
    $pct = $maxIPCount > 0 ? ($ipRow['c'] / $maxIPCount) * 100 : 0;
?>
<div class="group cursor-default">
<div class="flex justify-between text-body-base mb-base">
<span class="font-data-mono text-data-mono group-hover:text-primary transition-colors"><?= htmlspecialchars($ipRow['ip_address']) ?></span>
<span class="font-data-mono text-data-mono text-outline"><?= number_format($ipRow['c']) ?> hits</span>
</div>
<div class="w-full bg-surface-container-high h-1 rounded-full overflow-hidden">
<div class="bg-primary h-full" style="width: <?= $pct ?>%"></div>
</div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
</div>
<!-- Top Usernames -->
<div>
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">TOP USERNAMES ATTEMPTED</h4>
<div class="space-y-xs">
<?php if (empty($topUsersList)): ?>
<p class="text-on-surface-variant text-sm">No username data available.</p>
<?php else: ?>
<?php foreach ($topUsersList as $index => $userRow): ?>
<div class="flex items-center gap-md p-xs hover:bg-surface-container-low transition-colors rounded">
<div class="<?= $index === 0 ? 'bg-primary/10 text-primary' : 'bg-surface-container-highest text-outline' ?> w-8 h-8 rounded flex items-center justify-center font-bold text-xs"><?= $index + 1 ?></div>
<span class="font-data-mono text-data-mono flex-grow"><?= htmlspecialchars($userRow['attempted_username']) ?></span>
<span class="status-pill bg-surface-container text-on-surface-variant"><?= number_format($userRow['c']) ?></span>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
</div>
<!-- Top Passwords -->
<div>
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">ATTACK PATTERN DISTRIBUTION</h4>
<div class="space-y-sm">
<div class="relative pt-1">
<div class="flex mb-1 items-center justify-between">
<span class="font-data-mono text-data-mono text-on-surface-variant">SQL Injection</span>
<span class="font-data-mono text-data-mono text-xs text-outline"><?= $sqliPercent ?>%</span>
</div>
<div class="overflow-hidden h-1.5 mb-2 text-xs flex rounded bg-surface-container">
<div class="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-error" style="width:<?= $sqliPercent ?>%"></div>
</div>
</div>
<div class="relative pt-1">
<div class="flex mb-1 items-center justify-between">
<span class="font-data-mono text-data-mono text-on-surface-variant">Brute Force</span>
<span class="font-data-mono text-data-mono text-xs text-outline"><?= $bruteForcePercent ?>%</span>
</div>
<div class="overflow-hidden h-1.5 mb-2 text-xs flex rounded bg-surface-container">
<div class="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-tertiary" style="width:<?= $bruteForcePercent ?>%"></div>
</div>
</div>
<div class="relative pt-1">
<div class="flex mb-1 items-center justify-between">
<span class="font-data-mono text-data-mono text-on-surface-variant">Path Traversal</span>
<span class="font-data-mono text-data-mono text-xs text-outline"><?= $pathTraversalPercent ?>%</span>
</div>
<div class="overflow-hidden h-1.5 mb-2 text-xs flex rounded bg-surface-container">
<div class="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-primary/40" style="width:<?= $pathTraversalPercent ?>%"></div>
</div>
</div>
</div>
</div>
<!-- Top Passwords -->
<div>
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">TOP PASSWORDS ATTEMPTED</h4>
<div class="space-y-sm">
<?php if (empty($topPasswords)): ?>
<p class="text-on-surface-variant text-sm">No password data available.</p>
<?php else: ?>
<?php 
$maxPassCount = $topPasswords[0]['c']; 
foreach ($topPasswords as $passRow): 
    $pct = $maxPassCount > 0 ? ($passRow['c'] / $maxPassCount) * 100 : 0;
?>
<div class="relative pt-1">
<div class="flex mb-1 items-center justify-between">
<span class="font-data-mono text-data-mono text-on-surface-variant"><?= htmlspecialchars($passRow['attempted_password']) ?></span>
<span class="font-data-mono text-data-mono text-xs text-outline"><?= number_format($passRow['c']) ?> attempts</span>
</div>
<div class="overflow-hidden h-1.5 mb-2 text-xs flex rounded bg-surface-container">
<div class="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-primary" style="width:<?= $pct ?>%"></div>
</div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
</div>
<!-- Call to Action -->
</div>
</div>
</aside>
</div>

<!-- Heatmap -->
<div class="glass-card mt-lg overflow-x-auto">
<h4 class="font-label-caps text-label-caps text-on-surface-variant mb-md">ATTACK INTENSITY HEATMAP (DAY × HOUR)</h4>
<div class="min-w-[800px]">
    <div class="flex">
        <div class="w-12"></div>
        <?php for($h=0; $h<24; $h++): ?>
            <div class="flex-1 text-center font-data-mono text-[10px] text-outline"><?= str_pad($h, 2, '0', STR_PAD_LEFT) ?></div>
        <?php endfor; ?>
    </div>
    <?php foreach($daysOfWeek as $dNum => $dName): ?>
    <div class="flex items-center mt-1">
        <div class="w-12 font-data-mono text-[10px] text-on-surface-variant text-right pr-2"><?= $dName ?></div>
        <?php for($h=0; $h<24; $h++): 
            $val = $heatmapData[$dNum][$h];
            $opacity = $maxHeat > 0 ? ($val / $maxHeat) : 0;
            if ($val > 0 && $opacity < 0.2) $opacity = 0.2; 
        ?>
            <div class="flex-1 aspect-square mx-[1px] rounded-sm group relative cursor-crosshair transition-all hover:scale-110 hover:z-10" style="background-color: rgba(0, 102, 113, <?= $opacity ?>); <?= $val == 0 ? 'background-color: #eaeff0;' : '' ?>">
                <!-- Tooltip -->
                <div class="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block z-50 bg-inverse-surface text-on-inverse-surface text-[10px] py-1 px-2 rounded whitespace-nowrap font-data-mono shadow-lg">
                    <?= $dName ?> <?= str_pad($h, 2, '0', STR_PAD_LEFT) ?>:00<br><?= $val ?> attacks
                </div>
            </div>
        <?php endfor; ?>
    </div>
    <?php endforeach; ?>
    <div class="flex items-center justify-end gap-2 mt-4 text-[10px] font-label-caps text-outline">
        <span>Low</span>
        <div class="flex gap-[1px]">
            <div class="w-3 h-3 rounded-sm bg-[#eaeff0]"></div>
            <div class="w-3 h-3 rounded-sm" style="background-color: rgba(0, 102, 113, 0.3)"></div>
            <div class="w-3 h-3 rounded-sm" style="background-color: rgba(0, 102, 113, 0.6)"></div>
            <div class="w-3 h-3 rounded-sm" style="background-color: rgba(0, 102, 113, 1)"></div>
        </div>
        <span>High</span>
    </div>
</div>
</div>

<!-- System Status Footer -->
<footer class="mt-xl py-lg border-t border-outline-variant/30 flex flex-col md:flex-row justify-between items-center text-outline text-[12px]">
<div class="flex items-center gap-sm text-xs text-on-surface-variant">
<span class="flex items-center gap-xs">
<span class="material-symbols-outlined text-[14px]" data-weight="fill">wifi</span>
                    Live Data Feed Active
                </span>
<span>•</span>
<span>Last Updated: <?= htmlspecialchars($lastUpdatedDisplay) ?></span>
</div>
</footer>
</main>
<!-- Floating Action: Quick Investigation -->
<div class="fixed bottom-lg right-lg z-40">
<button class="flex items-center gap-sm bg-surface-bright text-on-surface px-lg py-md rounded-full shadow-lg border border-outline-variant/50 hover:shadow-xl transition-shadow group">
<span class="material-symbols-outlined text-primary group-hover:rotate-12 transition-transform">biotech</span>
<span class="font-bold tracking-tight">INVESTIGATE AGENT</span>
</button>
</div>
</body></html>