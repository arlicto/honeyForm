<?php
require_once 'db.php';
ensure_session_started();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Log the attack attempt
    $attackType = detect_attack_type([
        'username' => $username,
        'password' => $password,
        'user_agent' => $userAgent,
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
        'params' => $_POST,
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'POST'
    ]);

    $payloadData = $_POST;
    $payloadData['request_uri'] = $_SERVER['REQUEST_URI'] ?? '';
    $payload = json_encode($payloadData);
    $method = $_SERVER['REQUEST_METHOD'];
    $geo = getGeoLocation($ip);

    try {
        $stmtIP = $pdo->prepare("INSERT INTO ip_tracking (ip_address, country_code, country_name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE total_attacks = total_attacks + 1, country_code = VALUES(country_code), country_name = VALUES(country_name)");
        $stmtIP->execute([$ip, $geo['country_code'], $geo['country_name']]);
        
        $stmtGetIP = $pdo->prepare("SELECT id FROM ip_tracking WHERE ip_address = ?");
        $stmtGetIP->execute([$ip]);
        $ip_id = $stmtGetIP->fetchColumn();

        $stmt = $pdo->prepare("INSERT INTO attack_logs (ip_id, user_agent, attempted_username, attempted_password, attack_type, http_method, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$ip_id, $userAgent, $username, $password, $attackType, $method, $payload]);
    } catch (\PDOException $e) {
        // Handle silently for the honeypot
    }
    
    // Display a generic error message to keep the illusion
    $error = "500 Internal Server Error: Database connection failed.";

    // Simulate realistic backend latency for decoy POST responses.
    // Configurable via environment variables DECOY_MIN_DELAY_MS and DECOY_MAX_DELAY_MS (milliseconds).
    try {
        $minMs = getenv('DECOY_MIN_DELAY_MS') !== false ? (int)getenv('DECOY_MIN_DELAY_MS') : 400;
        $maxMs = getenv('DECOY_MAX_DELAY_MS') !== false ? (int)getenv('DECOY_MAX_DELAY_MS') : 1200;
        if ($maxMs < $minMs) { $maxMs = $minMs; }
        $delayMs = random_int($minMs, $maxMs);
        // usleep takes microseconds
        usleep($delayMs * 1000);
    } catch (\Throwable $e) {
        // Ignore any failures in delay simulation to keep honeypot resilient
    }
}
?>
<!DOCTYPE html>

<html class="light" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20100%20100'><rect%20width='100'%20height='100'%20rx='15'%20fill='%23006671'/><text%20x='50'%20y='60'%20font-size='60'%20text-anchor='middle'%20fill='white'%20font-family='Arial'>H</text></svg>"/>
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
          },
        },
      }
    </script>
<style>
        .glass-surface {
            background: rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid #E2E8F0;
        }
        .main-canvas {
            background: radial-gradient(circle at top right, #f5fafb 0%, #dde4e6 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body class="main-canvas font-body-base text-on-surface selection:bg-primary-fixed selection:text-on-primary-fixed overflow-hidden">
<!-- Suppression of TopNavBar and SideNavBar for Transactional/Login Screen -->
<div class="flex items-center justify-center min-h-screen px-lg relative">
<!-- Subtle Academic Decorative Elements (Forensic Aesthetic) -->
<div class="absolute top-0 left-0 p-lg opacity-20 hidden md:block">
<div class="flex flex-col gap-base">
<span class="font-data-mono text-label-caps text-secondary uppercase">Node: Lab_Instance_04</span>
<span class="font-data-mono text-label-caps text-secondary uppercase">Lat: 34.0522° N, Lon: 118.2437° W</span>
</div>
</div>
<!-- Login Container -->
<div class="w-full max-w-[440px] z-10">
<!-- Branding Header -->
<div class="flex flex-col items-center mb-xl text-center">
<div class="mb-md">
<img alt="Honeyform Logo" class="h-16 w-auto object-contain" src="https://lh3.googleusercontent.com/aida-public/AB6AXuDdX6mu963-xr4lVm8QRfWlQuSv_8SjGIF0WPgzL2QWpBMm87V-XRgQvYHGseJQ3FugQIt71HwXBZnKGOuAEL4E_Dlvu2z-E15TL6SEGp2OfFBsqPwE-J1F1A7s86ezZ0Cp0SCA66bEnla8gzydvFqzXE9AX_V5hXJs9I1HwHTTZfh5Yj5AACGEm_Kv8oTkXB8jLRyEdqjl7DrVPZ8BDFEY3OsrdGPjv52WuksM-g_PDrPQWs2Ue3i5ffabs4ZQfL2HKf_cGaxmPvQ"/>
</div>
<h1 class="font-display text-display text-on-surface tracking-tight mb-xs">Honeyform Admin Access</h1>
<div class="flex items-center gap-xs">
<span class="material-symbols-outlined text-[18px] text-primary" style="font-variation-settings: 'FILL' 0;">verified_user</span>
<p class="font-label-caps text-label-caps text-secondary uppercase tracking-widest">Authorized personnel only</p>
</div>
</div>
<!-- Glassmorphism Login Card -->
<div class="glass-surface rounded-[10px] p-md shadow-[0_8px_32px_rgba(0,0,0,0.04)]">
<?php if ($error): ?>
<div class="bg-error-container text-error p-sm rounded-lg mb-md text-sm font-bold border border-error/20">
    <?= htmlspecialchars($error) ?>
</div>
<?php endif; ?>
<form class="space-y-md" method="POST" action="">
<!-- Username Input -->
<div class="space-y-xs">
<label class="font-label-caps text-label-caps text-on-surface-variant uppercase ml-base" for="username">Admin Username</label>
<div class="relative">
<input class="w-full h-12 px-md bg-white border border-outline-variant rounded-lg font-body-base text-on-surface placeholder:text-outline focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all shadow-sm" id="username" name="username" placeholder="e.g. s_analyst_01" type="text"/>
<div class="absolute inset-y-0 right-0 pr-md flex items-center pointer-events-none">
<span class="material-symbols-outlined text-outline-variant text-[20px]">person</span>
</div>
</div>
</div>
<!-- Password Input -->
<div class="space-y-xs">
<label class="font-label-caps text-label-caps text-on-surface-variant uppercase ml-base" for="password">Admin Password</label>
<div class="relative">
<input class="w-full h-12 px-md bg-white border border-outline-variant rounded-lg font-body-base text-on-surface placeholder:text-outline focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all shadow-sm" id="password" name="password" placeholder="••••••••••••" type="password"/>
<div class="absolute inset-y-0 right-0 pr-md flex items-center pointer-events-none">
<span class="material-symbols-outlined text-outline-variant text-[20px]">lock</span>
</div>
</div>
</div>
<!-- Warning Subtext (Academic/Forensic) -->
<div class="flex gap-xs p-sm bg-surface-container-low rounded-lg border border-outline-variant/30">
<span class="material-symbols-outlined text-tertiary text-[18px]">info</span>
<p class="text-[12px] leading-tight text-on-surface-variant italic">
                            System access is monitored and logged in compliance with forensic security protocols. Unauthorized attempts will be investigated.
                        </p>
</div>
<!-- Login Button -->
<button class="w-full h-12 bg-primary text-on-primary font-headline-md text-headline-md rounded-lg hover:bg-primary-container transition-colors duration-200 flex items-center justify-center gap-sm active:scale-[0.98] transform" type="submit">
                        Login to Terminal
                        <span class="material-symbols-outlined text-[20px]">arrow_forward</span>
</button>
</form>
</div>
<!-- Footer Meta -->
<div class="mt-lg flex flex-col items-center gap-xs">
<div class="flex items-center gap-base">
<span class="material-symbols-outlined text-outline text-[14px]">shield</span>
<span class="font-body-base text-label-caps text-outline uppercase">Secure authentication required</span>
</div>
<div class="flex gap-md mt-sm">
<span class="font-label-caps text-[10px] text-outline uppercase">Network Status: Nominal</span>
<span class="text-outline-variant">•</span>
<span class="font-label-caps text-[10px] text-outline uppercase">Encryption: AES-256</span>
</div>
</div>
</div>
<!-- Forensic Background Texture (Grid & Lines) -->
<div class="absolute inset-0 pointer-events-none overflow-hidden opacity-[0.03]">
<div class="w-full h-full" style="background-image: linear-gradient(#171c1d 1px, transparent 1px), linear-gradient(90deg, #171c1d 1px, transparent 1px); background-size: 40px 40px;"></div>
</div>
</div>
<!-- Background Forensic Image Accent -->
<div class="fixed bottom-0 right-0 w-1/3 h-1/2 opacity-10 pointer-events-none grayscale brightness-110 contrast-125 mix-blend-multiply">
<img class="w-full h-full object-cover" data-alt="A macro close-up of high-performance server circuitry and glass panels with glowing data points. The lighting is cold and clinical, featuring soft teal and charcoal gray accents that match the laboratory research aesthetic. The composition uses a shallow depth of field, highlighting the precision of the hardware against a pristine, bright background. The mood is highly intellectual, focusing on technical clarity and forensic detail." src="https://lh3.googleusercontent.com/aida-public/AB6AXuDDTJ8YkSlZFzMLGsNEmJvXM_NIuEuXvZS6BSPtzvp2GyefwMlBB2NJ9Lqinn0QnmRdY4gnplZSFiv5YqZioGDoWDPfuE41uQloKnpJ4KeirCibJY6f0o08RSz5X9qj08YOKMqABdntlDyo9s3fhni-POVQ74xwO8W1S5v1hhrAdRl4vpK1-nYHrOruVRTssQp1oKgBuJ6EyLnr_lp6Cx7vHhDl2lSmz3Xz3kLNRBUnaokvTkvbKqG49-CIVTsAcnFG9AfNmK40kus"/>
</div>

<!-- Footer -->
<footer class="max-w-[1600px] mx-auto px-lg py-md border-t border-outline-variant/30 mt-xl flex justify-between items-center text-on-surface-variant">
    <div class="flex gap-md items-center font-label-caps text-label-caps">
        <span>Server: Lab-Node-04</span>
        <span class="text-outline-variant">|</span>
        <span>Last Updated: <?= htmlspecialchars(date('Y-m-d H:i:s')) ?> UTC</span>
    </div>
    <span class="font-data-mono text-[12px]">Decoy</span>
</footer>
<script>
function togglePassword(id, btn){
    var el = document.getElementById(id);
    if(!el) return;
    if(el.type === 'password'){ el.type = 'text'; btn.textContent = 'Hide'; } else { el.type = 'password'; btn.textContent = 'Show'; }
}
</script>
</body></html>
# 1780424314458291379

# 1780769913102401930
