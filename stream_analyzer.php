<?php
require_once 'db.php';
ensure_session_started();
if (empty($_SESSION['is_admin'])) {
    http_response_code(404);
    echo 'Not Found';
    exit;
}


$filterIp = trim($_GET['ip'] ?? '');
$filterUsername = trim($_GET['username'] ?? '');
$filterType = trim($_GET['type'] ?? '');
$filterStartRaw = trim($_GET['start_date'] ?? '');
$filterEndRaw = trim($_GET['end_date'] ?? '');

// CSRF: require a valid token when filters are provided to prevent CSRF on the filter form
$hasFilters = ($filterIp !== '' || $filterUsername !== '' || $filterType !== '' || $filterStartRaw !== '' || $filterEndRaw !== '');
$csrfToken = $_GET['csrf_token'] ?? '';
if ($hasFilters && !verify_csrf_token($csrfToken)) {
    $filterIp = $filterUsername = $filterType = '';
    $filterStartRaw = $filterEndRaw = '';
    $csrfError = 'Invalid CSRF token.';
}

// Normalize and validate date inputs (expected format: YYYY-MM-DD)
$filterStart = null;
$filterEnd = null;
$filterStartValue = '';
$filterEndValue = '';
if ($filterStartRaw !== '') {
    $dt = DateTime::createFromFormat('Y-m-d', $filterStartRaw);
    if (!$dt) {
        $dt = DateTime::createFromFormat('Y-m-d\TH:i', $filterStartRaw);
    }
    if ($dt) {
        $dt->setTime(0, 0, 0);
        $filterStart = $dt->format('Y-m-d H:i:s');
        $filterStartValue = $dt->format('Y-m-d');
    }
}
if ($filterEndRaw !== '') {
    $dt = DateTime::createFromFormat('Y-m-d', $filterEndRaw);
    if (!$dt) {
        $dt = DateTime::createFromFormat('Y-m-d\TH:i', $filterEndRaw);
    }
    if ($dt) {
        $dt->setTime(23, 59, 59);
        $filterEnd = $dt->format('Y-m-d H:i:s');
        $filterEndValue = $dt->format('Y-m-d');
    }
}

try {
    $where = [];
    $params = [];

    if ($filterIp !== '') {
        $where[] = 'ip.ip_address LIKE ?';
        $params[] = '%' . $filterIp . '%';
    }

    if ($filterUsername !== '') {
        $where[] = 'al.attempted_username LIKE ?';
        $params[] = '%' . $filterUsername . '%';
    }

    if ($filterType !== '') {
        $where[] = 'al.attack_type = ?';
        $params[] = $filterType;
    }

    if ($filterStart !== null) {
        $where[] = 'al.timestamp >= ?';
        $params[] = $filterStart;
    }

    if ($filterEnd !== null) {
        $where[] = 'al.timestamp <= ?';
        $params[] = $filterEnd;
    }

    $sql = "
        SELECT al.*, ip.ip_address, ip.country_code, ip.country_name
        FROM attack_logs al
        JOIN ip_tracking ip ON al.ip_id = ip.id
    ";

    if (!empty($where)) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }

    // Pagination
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = 50;
    $offset = ($page - 1) * $perPage;

    // Get total count for pagination
    $countSql = "SELECT COUNT(*) FROM attack_logs al JOIN ip_tracking ip ON al.ip_id = ip.id";
    if (!empty($where)) {
        $countSql .= ' WHERE ' . implode(' AND ', $where);
    }
    $stmtCount = $pdo->prepare($countSql);
    $stmtCount->execute($params);
    $totalRows = (int)$stmtCount->fetchColumn();
    $totalPages = max(1, (int)ceil($totalRows / $perPage));

    $sql .= ' ORDER BY al.timestamp DESC LIMIT ' . (int)$perPage . ' OFFSET ' . (int)$offset;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $logs = $stmt->fetchAll();

    // Export CSV logic
    if (isset($_GET['export']) && $_GET['export'] === 'csv') {
        $exportSql = "
            SELECT al.timestamp, ip.ip_address, ip.country_name, al.attack_type, al.http_method, al.attempted_username, al.attempted_password, al.user_agent, al.raw_payload
            FROM attack_logs al
            JOIN ip_tracking ip ON al.ip_id = ip.id
        ";
        if (!empty($where)) {
            $exportSql .= ' WHERE ' . implode(' AND ', $where);
        }
        $exportSql .= ' ORDER BY al.timestamp DESC';
        
        $stmtExport = $pdo->prepare($exportSql);
        $stmtExport->execute($params);
        
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="honeyform_logs_' . date('Y-m-d_H-i-s') . '.csv"');
        
        $output = fopen('php://output', 'w');
        // Add UTF-8 BOM for Excel compatibility
        fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
        fputcsv($output, ['Timestamp', 'IP Address', 'Country', 'Attack Type', 'HTTP Method', 'Username', 'Password', 'User Agent', 'Payload']);
        
        while ($row = $stmtExport->fetch(PDO::FETCH_ASSOC)) {
            fputcsv($output, $row);
        }
        fclose($output);
        exit;
    }

    
    // IP Alerting Feature: Find IPs with >= 5 attempts
    $stmtAlerts = $pdo->query("SELECT ip_address FROM ip_tracking WHERE total_attacks >= 5");
    $flaggedIPs = $stmtAlerts->fetchAll(PDO::FETCH_COLUMN);

    // Determine most active IP for the current date (avoid exposing static placeholders)
    $stmtMostActive = $pdo->prepare("
        SELECT ip.ip_address, ip.country_code, ip.country_name, COUNT(*) AS reqs
        FROM attack_logs al
        JOIN ip_tracking ip ON al.ip_id = ip.id
        WHERE DATE(al.timestamp) = CURRENT_DATE
        GROUP BY ip.id, ip.ip_address, ip.country_code, ip.country_name
        ORDER BY reqs DESC
        LIMIT 1
    ");
    $stmtMostActive->execute();
    $mostActive = $stmtMostActive->fetch();
    $mostActiveIp = $mostActive['ip_address'] ?? 'N/A';
    $mostActiveReqs = (int)($mostActive['reqs'] ?? 0);
    $mostActiveCountryName = $mostActive['country_name'] ?? 'Unknown';
    $mostActiveCountryCode = $mostActive['country_code'] ?? 'XX';

    // Build a dynamic narrative for the most active IP using the most common raw_payload (or a representative snippet)
    $mostActiveNarrative = '';
    if (!empty($mostActive) && $mostActiveIp !== 'N/A') {
        try {
            $mostActiveNarrative = "Originating from {$mostActiveCountryName}, {$mostActiveCountryCode}. {$mostActiveReqs} suspicious requests intercepted today.";
        } catch (\Exception $e) {
            $mostActiveNarrative = "Originating from {$mostActiveCountryName}, {$mostActiveCountryCode}. Activity detected.";
        }
    } else {
        $mostActiveNarrative = 'No activity recorded for today.';
    }

    // Last-updated timestamp from logs (use real data instead of a static value)
    try {
        $stmtLast = $pdo->query("SELECT MAX(timestamp) AS last_update FROM attack_logs");
        $lastUpdated = $stmtLast->fetchColumn();
        $lastUpdatedDisplay = $lastUpdated ? date('Y-m-d H:i:s', strtotime($lastUpdated)) . ' UTC' : 'N/A';

        // Attack type percentages (shared helper)
        $attackTypePercents = stats_get_attack_type_percentages($pdo);
        $sqliPercent = $attackTypePercents['SQLi'] ?? 0;
        $bruteForcePercent = $attackTypePercents['Brute Force'] ?? 0;
        $pathTraversalPercent = $attackTypePercents['Path Traversal'] ?? 0;

    } catch (\PDOException $e) {
        $lastUpdatedDisplay = 'N/A';
    }
} catch (\PDOException $e) {
    $logs = [];
    $flaggedIPs = [];
    $mostActiveIp = 'N/A';
    $mostActiveReqs = 0;
    $mostActiveCountryName = 'Unknown';
    $mostActiveCountryCode = 'XX';
}
?>
<!DOCTYPE html>

<html class="light" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Honeyform | Forensic Logs</title>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@450&amp;display=swap" rel="stylesheet"/>
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
        }
        .suspicious-row {
            background-color: rgba(255, 218, 214, 0.3);
        }
        .suspicious-row:hover {
            background-color: rgba(255, 218, 214, 0.5) !important;
        }
    </style>
</head>
<body class="bg-background font-body-base text-on-surface min-h-screen">
<!-- TopNavBar -->
<header class="flex justify-between items-center px-lg py-sm w-full sticky top-0 z-50 bg-surface/70 backdrop-blur-xl border-b border-outline-variant/30 shadow-sm">
<div class="flex items-center gap-md">
<span class="font-display text-headline-md font-bold text-on-surface">Honeyform</span>
<nav class="hidden md:flex items-center space-x-md ml-lg">
<a class="text-on-surface-variant font-medium pb-2 hover:text-primary transition-colors duration-200" href="command_hub_a1.php">Dashboard</a>
<a class="text-primary border-b-2 border-primary font-bold pb-2" href="stream_analyzer.php">Logs</a>
</nav>
</div>
<div class="flex items-center gap-sm">
<div class="hidden md:block relative">
<form method="GET" action="stream_analyzer.php" class="flex items-center">
    <input name="ip" class="bg-surface-container-low border border-outline-variant/50 rounded-lg px-md py-xs text-body-base focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all" placeholder="Search logs..." type="text" value="<?= htmlspecialchars($filterIp) ?>" />
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>" />
    <button type="submit" class="material-symbols-outlined absolute right-2 top-2 text-on-surface-variant">search</button>
</form>
</div>
</div>
</header>
<main class="max-w-[1600px] mx-auto px-lg py-lg grid grid-cols-1 lg:grid-cols-12 gap-lg">
<!-- Filter Bar (Top of Main) -->
<form class="lg:col-span-12 glass-card flex flex-wrap items-center gap-md p-md" method="GET" action="stream_analyzer.php">
            <?php if (!empty($csrfError)): ?>
                <div class="bg-error-container text-error p-3 rounded mb-4 text-sm font-bold"><?= htmlspecialchars($csrfError) ?></div>
            <?php endif; ?>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generate_csrf_token()) ?>" />
<div class="grid grid-cols-1 gap-md">
<!-- Row 1: Search Fields -->
<div class="flex flex-wrap items-center gap-lg">
<div class="flex-1 min-w-[250px]">
<label class="font-label-caps text-label-caps text-on-surface-variant mb-xs block">SEARCH BY IP</label>
<input class="w-full bg-white border border-outline-variant/50 rounded-lg px-sm py-xs text-body-base focus:ring-1 focus:ring-primary outline-none" name="ip" placeholder="192.168.1.1" type="text" value="<?= htmlspecialchars($filterIp) ?>"/>
</div>
<div class="flex-1 min-w-[250px]">
<label class="font-label-caps text-label-caps text-on-surface-variant mb-xs block">USERNAME</label>
<input class="w-full bg-white border border-outline-variant/50 rounded-lg px-sm py-xs text-body-base focus:ring-1 focus:ring-primary outline-none" name="username" placeholder="admin" type="text" value="<?= htmlspecialchars($filterUsername) ?>"/>
</div>
</div>
<!-- Row 2: Status, Time, and Button -->
<div class="flex flex-wrap items-end gap-lg">
<div class="w-48">
<label class="font-label-caps text-label-caps text-on-surface-variant mb-xs block">TYPE</label>
<select class="w-full bg-white border border-outline-variant/50 rounded-lg px-sm py-xs text-body-base focus:ring-1 focus:ring-primary outline-none" name="type">
<option value="" <?= $filterType === '' ? 'selected' : '' ?>>All types</option>
<option value="Brute Force" <?= $filterType === 'Brute Force' ? 'selected' : '' ?>>Brute Force</option>
<option value="SQLi" <?= $filterType === 'SQLi' ? 'selected' : '' ?>>SQLi</option>
<option value="Path Traversal" <?= $filterType === 'Path Traversal' ? 'selected' : '' ?>>Path Traversal</option>
<option value="Scanner" <?= $filterType === 'Scanner' ? 'selected' : '' ?>>Scanner</option>
</select>
</div>
<div class="flex-1 min-w-[300px]">
<label class="font-label-caps text-label-caps text-on-surface-variant mb-xs block">TIME RANGE</label>
<div class="flex items-center gap-sm">
<input name="start_date" class="w-full bg-white border border-outline-variant/50 rounded-lg px-sm py-xs text-body-base focus:ring-1 focus:ring-primary outline-none" type="date" value="<?= htmlspecialchars($filterStartValue) ?>" />
<span class="text-on-surface-variant">to</span>
<input name="end_date" class="w-full bg-white border border-outline-variant/50 rounded-lg px-sm py-xs text-body-base focus:ring-1 focus:ring-primary outline-none" type="date" value="<?= htmlspecialchars($filterEndValue) ?>" />
</div>
</div>
<div class="flex flex-wrap items-end gap-md">
    <button class="bg-primary text-on-primary px-xl py-sm rounded-lg font-bold hover:opacity-90 transition-all active:scale-95 whitespace-nowrap" type="submit">Execute Query</button>
    <button name="export" value="csv" class="bg-surface-container-high text-on-surface px-lg py-sm rounded-lg font-bold hover:bg-surface-container-highest transition-all active:scale-95 whitespace-nowrap flex items-center gap-xs" type="submit">
        <span class="material-symbols-outlined text-[20px]">download</span>
        Export CSV
    </button>
</div>
</div>
</div>
</form>
<!-- Forensic Table Canvas -->
<div class="lg:col-span-9 space-y-md">
<div class="glass-card overflow-hidden">
<div class="px-md py-sm border-b border-outline-variant/30 bg-surface-container-low flex justify-between items-center">
<h2 class="font-headline-md text-headline-md text-on-surface">Raw Intelligence Stream</h2>
<span class="flex items-center gap-xs font-label-caps text-label-caps text-primary">
<span class="material-symbols-outlined text-[14px]" data-weight="fill">refresh</span>
                        Live Stream Active
                    </span>
</div>
<div class="overflow-x-auto">
<table class="w-full text-left border-collapse">
<thead class="bg-surface-container/50 font-label-caps text-label-caps text-on-surface-variant border-b border-outline-variant/30">
<tr>
<th class="px-md py-sm font-bold">Timestamp</th>
<th class="px-md py-sm font-bold">IP Address</th>
<th class="px-md py-sm font-bold">Username</th>
<th class="px-md py-sm font-bold">Password</th>
<th class="px-md py-sm font-bold">Method</th>
<th class="px-md py-sm font-bold">Flag</th>
</tr>
</thead>
<tbody class="font-data-mono text-data-mono text-on-surface">
<?php if (empty($logs)): ?>
<tr class="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
<td colspan="6" class="px-md py-sm text-center text-outline">No attacks logged yet. Waiting for honey...</td>
</tr>
<?php else: ?>
    <?php foreach ($logs as $log): ?>
    <?php
        $type = $log['attack_type'];
        $isSuspicious = in_array($type, ['SQLi', 'Path Traversal']);
        $rowClass = $isSuspicious ? 'suspicious-row ' : '';
        $rowClass .= 'border-b border-outline-variant/10 hover:bg-primary/5 transition-colors group cursor-default';
        
        if ($type === 'SQLi') {
            $flagClass = 'bg-error-container text-error'; // Red
        } elseif ($type === 'Brute Force') {
            $flagClass = 'bg-tertiary-container text-on-tertiary-container'; // Orange
        } else {
            $flagClass = 'bg-secondary-container text-on-secondary-container'; // Default
        }
    ?>
    <tr class="<?= $rowClass ?>">
        <td class="px-md py-sm"><?= htmlspecialchars($log['timestamp']) ?></td>
        <td class="px-md py-sm text-primary">
            <?= htmlspecialchars($log['ip_address']) ?>
            <?php if (in_array($log['ip_address'], $flaggedIPs)): ?>
                <span class="ml-2 bg-error text-white px-xs py-[2px] rounded text-[10px] font-bold" title="Repeated attacks detected">ALERT</span>
            <?php endif; ?>
        </td>
        <td class="px-md py-sm"><?= htmlspecialchars($log['attempted_username']) ?></td>
        <td class="px-md py-sm italic text-on-surface-variant/70">
            <?php $pwd = $log['attempted_password'] ?? ''; $pwd_attr = htmlspecialchars($pwd, ENT_QUOTES); $pwd_mask = $pwd !== '' ? str_repeat('•', min(8, strlen($pwd))) : ''; ?>
            <div class="flex items-center gap-sm">
                <span class="password-mask font-data-mono" data-password="<?= $pwd_attr ?>" data-password-masked="<?= htmlspecialchars($pwd_mask, ENT_QUOTES) ?>"><?= htmlspecialchars($pwd_mask) ?></span>
                <div class="ml-2 flex items-center gap-2">
                    <button type="button" class="bg-surface-container px-xs py-[2px] rounded text-[10px] font-bold" onclick="(function(btn){const td=btn.closest('td');const sp=td.querySelector('.password-mask'); if(sp.dataset.revealed==='1'){sp.textContent=sp.dataset.passwordMasked; sp.dataset.revealed='0'; btn.textContent='Reveal'; } else {sp.textContent=sp.dataset.password; sp.dataset.revealed='1'; btn.textContent='Hide';}})(this)">Reveal</button>
                    <button type="button" class="bg-surface-container px-xs py-[2px] rounded text-[10px] font-bold" onclick="(function(btn){const td=btn.closest('td');const sp=td.querySelector('.password-mask'); const toCopy=sp.dataset.password||''; if(!toCopy){btn.textContent='Empty'; setTimeout(()=>btn.textContent='Copy',1500); return;} if(navigator.clipboard && navigator.clipboard.writeText){navigator.clipboard.writeText(toCopy).then(()=>{btn.textContent='Copied'; setTimeout(()=>btn.textContent='Copy',1500);}).catch(()=>{copyFallback(toCopy, btn);}); } else {copyFallback(toCopy, btn);} function copyFallback(text, btn){const ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy'); btn.textContent='Copied'; }catch(e){alert('Copy failed'); } document.body.removeChild(ta); setTimeout(()=>btn.textContent='Copy',1500);} })(this)">Copy</button>
                </div>
            </div>
        </td>
        <td class="px-md py-sm"><span class="bg-secondary-container text-on-secondary-container px-xs py-[2px] rounded text-[10px] font-bold"><?= htmlspecialchars(strtoupper($log['http_method'] ?? 'POST')) ?></span></td>
        <td class="px-md py-sm">
            <span class="<?= $flagClass ?> px-xs py-[2px] rounded text-[10px] font-bold"><?= htmlspecialchars(strtoupper($log['attack_type'])) ?></span>
        </td>
    </tr>
    <?php endforeach; ?>
<?php endif; ?>
</tbody>
</table>
</div>
<div class="p-md bg-surface-container-lowest flex justify-between items-center">
<span class="font-label-caps text-label-caps text-on-surface-variant">Total Logs Captured: <?= number_format($totalRows) ?></span>
<div class="flex gap-xs items-center">
    <?php
        // Build base query params preserving existing filters
        $baseParams = $_GET;
        unset($baseParams['page']);
        $prevPage = max(1, $page - 1);
        $nextPage = min($totalPages, $page + 1);
        $prevUrl = 'stream_analyzer.php?' . http_build_query(array_merge($baseParams, ['page' => $prevPage]));
        $nextUrl = 'stream_analyzer.php?' . http_build_query(array_merge($baseParams, ['page' => $nextPage]));
    ?>
    <a class="p-xs glass-card hover:bg-primary/5 transition-all material-symbols-outlined text-sm" href="<?= htmlspecialchars($prevUrl) ?>">chevron_left</a>
    <span class="p-xs glass-card bg-primary text-on-primary transition-all text-sm font-bold mt-auto">Page <?= $page ?> / <?= $totalPages ?></span>
    <a class="p-xs glass-card hover:bg-primary/5 transition-all material-symbols-outlined text-sm" href="<?= htmlspecialchars($nextUrl) ?>">chevron_right</a>
</div>
</div>
</div>
</div>
<!-- Sidebar Diagnostics -->
<aside class="lg:col-span-3 space-y-md">
<!-- Most Active IP -->
<div class="glass-card p-md">
<label class="font-label-caps text-label-caps text-on-surface-variant block mb-sm">MOST ACTIVE IP TODAY</label>
<div class="flex items-center justify-between mb-xs">
<span class="font-data-mono text-primary font-bold"><?= htmlspecialchars($mostActiveIp) ?></span>
<span class="font-label-caps text-label-caps text-on-surface-variant"><?= htmlspecialchars((string)$mostActiveReqs) ?> reqs</span>
</div>
<div class="w-full bg-surface-container h-1 rounded-full overflow-hidden">
<div class="bg-primary w-3/4 h-full"></div>
</div>
<p class="mt-md text-[12px] text-on-surface-variant leading-relaxed">
                    <?= htmlspecialchars($mostActiveNarrative) ?>
                </p>
</div>
<!-- Attack Pattern -->
<div class="glass-card p-md">
<label class="font-label-caps text-label-caps text-on-surface-variant block mb-sm">COMMON ATTACK PATTERN</label>
<div class="space-y-sm">
<div class="flex items-center justify-between">
<span class="text-body-base font-medium">SQL Injection</span>
<span class="font-label-caps text-label-caps bg-error-container text-error px-xs py-[2px] rounded"><?= htmlspecialchars((string)$sqliPercent) ?>%</span>
</div>
<div class="flex items-center justify-between">
<span class="text-body-base font-medium">Brute Force</span>
<span class="font-label-caps text-label-caps bg-tertiary-container text-on-tertiary-container px-xs py-[2px] rounded"><?= htmlspecialchars((string)$bruteForcePercent) ?>%</span>
</div>
<div class="flex items-center justify-between">
<span class="text-body-base font-medium">Path Traversal</span>
<span class="font-label-caps text-label-caps bg-secondary-container text-on-secondary-container px-xs py-[2px] rounded"><?= htmlspecialchars((string)$pathTraversalPercent) ?>%</span>
</div>
</div>
</div>
</aside>
</main>
<!-- Footer Meta -->
<footer class="max-w-[1600px] mx-auto px-lg py-md border-t border-outline-variant/30 mt-xl flex justify-between items-center text-on-surface-variant">
<div class="flex gap-md items-center font-label-caps text-label-caps">
<span>Server: Lab-Node-04</span>
<span class="text-outline-variant">|</span>
<span>Uptime: 99.98%</span>
</div>
<span class="font-data-mono text-[12px]">Hash: 8f2b...3a1c</span>
</footer>
</body></html>
# 1780424314007475171
