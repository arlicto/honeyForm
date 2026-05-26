# HoneyForm: Forensic Honeypot

HoneyForm is a professional-grade PHP/MySQL honeypot for high-fidelity attack simulation, real-time forensic logging, and interactive visualization. It lures attackers with a convincing fake admin login while providing security analysts with deep insight into malicious activity.

**Features:** Dual-interface architecture (bait + hidden admin) | Chart.js telemetry dashboard | Heuristic attack classification (SQLi, Path Traversal, Brute Force, Scanner) | IP geolocation | Pen-test tool detection | Forensic log viewer with CSV export | Local LLM insights via Ollama | Live traffic simulator

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup by Operating System](#setup-by-operating-system)
  - [Ubuntu / Debian](#ubuntu--debian)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Docker (any OS)](#docker-any-os)
- [Quick Start](#quick-start)
- [User Guide](#user-guide)
  - [Accessing the Admin Dashboard](#accessing-the-admin-dashboard)
  - [The Bait (Attacker View)](#the-bait-attacker-view)
  - [Dashboard Walkthrough](#dashboard-walkthrough)
  - [Forensic Log Viewer](#forensic-log-viewer)
  - [Live Log Generator](#live-log-generator)
  - [AI Security Insights](#ai-security-insights)
  - [Testing Attack Detection](#testing-attack-detection)
- [File Reference](#file-reference)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| PHP | 8.0 | 8.2+ |
| MySQL / MariaDB | 5.7 / 10.3 | 8.0 / 10.11 |
| Web Server | Apache 2.4 / Nginx / PHP built-in | Apache 2.4 |
| Extensions | `pdo_mysql`, `json`, `session`, `mbstring` | same |
| Ollama (optional) | — | latest (for AI insights) |
| Internet | Required for CDN assets (fonts, charts, geolocation) | — |

---

## Setup by Operating System

### Ubuntu / Debian

```bash
# 1. Install PHP, extensions, MySQL, and Apache
sudo apt update
sudo apt install -y php php-cli php-mysql php-xml php-json php-mbstring libapache2-mod-php mysql-server

# 2. Start services
sudo systemctl enable --now mysql
sudo systemctl enable --now apache2

# 3. Verify PDO MySQL
php -m | grep -i pdo_mysql || echo "pdo_mysql not enabled"

# 4. Secure MySQL (set a root password)
sudo mysql_secure_installation

# 5. Clone the project
cd /var/www/html
git clone https://github.com/arlicto/honeyForm.git
cd honeyForm

# 6. Configure environment
cp .env.example .env
# Edit .env — set DB_PASS to your MySQL root password
nano .env

# 7. Run database setup
php setup_db.php

# 8. Set permissions
sudo chown -R www-data:www-data .
sudo chmod -R 755 .

# 9. Access at http://localhost/honeyForm
```

**Apache virtual host (optional):**
```apache
<VirtualHost *:80>
    ServerName honeyform.local
    DocumentRoot /var/www/html/honeyForm
    <Directory /var/www/html/honeyForm>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

---

### macOS

#### Option A: Homebrew (Apache + PHP)

```bash
# 1. Install PHP and MySQL
brew update
brew install php mysql

# 2. Start services
brew services start mysql
brew services start php

# 3. Secure MySQL
mysql_secure_installation

# 4. Clone and configure
cd ~/Sites
git clone https://github.com/arlicto/honeyForm.git
cd honeyForm
cp .env.example .env
nano .env    # set DB_PASS to your MySQL root password

# 5. Run database setup
php setup_db.php

# 6. Start PHP development server
php -S localhost:8000

# 7. Access at http://localhost:8000
```

#### Option B: MAMP (GUI)

1. Download and install [MAMP](https://www.mamp.info/)
2. Start MAMP — Apache and MySQL should be running
3. Clone the repo into `/Applications/MAMP/htdocs/honeyForm/`
4. Copy `.env.example` to `.env`
5. Edit `.env` — use `DB_HOST=localhost`, `DB_USER=root`, `DB_PASS=root`
6. Open Terminal and run:
   ```bash
   cd /Applications/MAMP/htdocs/honeyForm
   /Applications/MAMP/bin/php/php8.2.0/bin/php setup_db.php
   ```
7. Access at `http://localhost:8888/honeyForm`

---

### Windows

#### Option A: XAMPP

1. Download and install [XAMPP](https://www.apachefriends.org/) (includes Apache, PHP, MySQL)
2. Open XAMPP Control Panel → Start **Apache** and **MySQL**
3. Clone the repo into `C:\xampp\htdocs\honeyForm\`
   ```powershell
   cd C:\xampp\htdocs
   git clone https://github.com/arlicto/honeyForm.git
   ```
4. Copy `.env.example` to `.env`:
   ```powershell
   copy .env.example .env
   ```
5. Edit `.env` (use Notepad) — set `DB_USER=root`, `DB_PASS=` (empty by default in XAMPP)
6. Open **Command Prompt as Administrator** and run:
   ```cmd
   cd C:\xampp\htdocs\honeyForm
   C:\xampp\php\php.exe setup_db.php
   ```
7. Access at `http://localhost/honeyForm`

#### Option B: WAMP

1. Download and install [WAMP](https://www.wampserver.com/)
2. Start WAMP → Apache and MySQL icons should be green
3. Clone the repo into `C:\wamp64\www\honeyForm\`
4. Copy `.env.example` to `.env`
5. Edit `.env` — `DB_USER=root`, `DB_PASS=` (empty by default in WAMP)
6. Open Command Prompt:
   ```cmd
   cd C:\wamp64\www\honeyForm
   C:\wamp64\bin\php\php8.2.0\php.exe setup_db.php
   ```
7. Access at `http://localhost/honeyForm`

#### Option C: PHP Built-in Server (no Apache needed)

1. Install PHP for Windows from [windows.php.net](https://windows.php.net/download/)
2. Ensure `php.ini` has `extension=pdo_mysql` and `extension=mbstring` uncommented
3. Install [MySQL Community Server](https://dev.mysql.com/downloads/mysql/)
4. Follow the clone + `.env` steps from XAMPP above
5. Run:
   ```cmd
   cd C:\path\to\honeyForm
   php -S localhost:8000
   ```
6. Access at `http://localhost:8000`

---

### Docker (any OS)

```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    image: php:8.2-apache
    ports:
      - "80:80"
    volumes:
      - ./:/var/www/html
    depends_on:
      - db
    command: >
      bash -c "docker-php-ext-install pdo_mysql && a2enmod rewrite && apache2-foreground"
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: honeyform_db
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

Then:
```bash
docker-compose up -d
docker-compose exec web bash
# Inside container:
cd /var/www/html
cp .env.example .env
# Edit .env: DB_HOST=db, DB_USER=root, DB_PASS=root
php setup_db.php
exit
# Access at http://localhost
```

---

## Quick Start

After completing the OS-specific setup above:

```bash
# 1. Verify the lock file was created (prevents accidental re-setup)
ls -la install.lock

# 2. Start the dev server (if not using Apache/Nginx)
php -S localhost:8000

# 3. Open the admin login
#    http://localhost:8000/staff_gate_7.php
#    Username: admin
#    Password: honey123

# 4. (Optional) Seed demo data for a populated dashboard
php live_log_generator.php seed
```

---

## User Guide

### Accessing the Admin Dashboard

The hidden admin portal is at **`staff_gate_7.php`**. This is never linked from any public page.

| Field | Value |
|---|---|
| URL | `http://your-server/staff_gate_7.php` |
| Default Username | `admin` |
| Default Password | `honey123` |

After login, you are redirected to the **Command Hub** (`command_hub_a1.php`).

> **Change the default password immediately in production.** Edit the `admin_accounts` table directly or run:
> ```sql
> UPDATE admin_accounts SET password_hash = SHA2('new_password', 256) WHERE username = 'admin';
> ```
> (Use `password_hash()` via PHP — the SQL above is just illustrative.)

### The Bait (Attacker View)

The public-facing page at `http://your-server/` routes to `gateway.php` — a convincing fake admin login. Every submission here is logged as an attack with full forensic metadata (IP, User-Agent, submitted credentials, HTTP method, timestamp). The attacker always receives a "500 Internal Server Error" response to maintain the illusion.

**Do not visit `gateway.php` yourself while logged into the admin — it will not trap you**, but all other visitors are captured.

### Dashboard Walkthrough

The Command Hub dashboard (`command_hub_a1.php`) is organized into these sections:

**Top Metrics Bar:**
- Total Login Attempts — lifetime count of all captured attacks
- Unique IP Addresses — distinct source IPs tracked
- Most Targeted Username — the username attackers try most often

**Login Attempts Over Time:**
- Toggle between Hourly (last 48 hours) and Daily (last 14 days) views
- Area chart with gradient fill shows attack volume trends

**Detected Pen-Test Tools:**
- Badge counters for sqlmap, nikto, hydra, and curl
- Color-coded by severity

**Geolocation Summary:**
- Top 5 attacking countries with bar chart percentages

**AI Security Insights:**
- Click "Generate Insights" to run local LLM analysis
- Returns markdown-formatted executive summary with bot vs. human classification
- Analysis is cached; polling happens automatically

**Attack Intensity Heatmap:**
- 7 (days) × 24 (hours) grid
- Darker cells = higher attack volume
- Hover for per-cell tooltip

**Sidebar Lists:**
- Top 10 IPs — ranked by total hits with horizontal bars
- Top 10 Usernames — most attempted credentials
- Attack Pattern Distribution — SQLi vs Brute Force vs Path Traversal percentages
- Top 10 Passwords — most submitted passwords with attempt counts

### Forensic Log Viewer

The Logs page (`stream_analyzer.php`) provides searchable, paginated access to all captured attacks.

**Filtering:**
- Search by IP (partial match)
- Filter by username
- Filter by attack type (Brute Force, SQLi, Path Traversal, Scanner)
- Filter by date range

**Features:**
- Password reveal/hide toggle per row
- "Copy" button to copy passwords to clipboard
- "ALERT" badge on IPs with 5+ attempts
- Attack type color-coding
- CSV export with current filters applied
- Pagination with page navigation

**CSV Export:** Click "Export CSV" to download filtered results as a UTF-8 CSV file compatible with Excel.

### Live Log Generator

CLI tool to populate the database with realistic attack data for demos and testing.

```bash
# Generate one attack every 3 seconds (default)
php live_log_generator.php

# Custom interval (every 5 seconds)
php live_log_generator.php 5

# Seed 7 days of historical data (populates charts and heatmaps)
php live_log_generator.php seed

# Clear all data, then seed history, then live-generate
php live_log_generator.php clear seed

# Clear all data and exit
php live_log_generator.php clear-only
```

The generator creates randomized attacks from 10 simulated IPs across 6 countries, using realistic user agents (including tool signatures), varying attack types, and time-of-day attack curves.

### AI Security Insights

Requires [Ollama](https://ollama.com/) with the `llama3.2:3b` model.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model
ollama pull llama3.2:3b

# Start Ollama (auto-starts as a service on most platforms)
ollama serve
```

On the dashboard, click **"Generate Insights"** to trigger background analysis of the last 50 logs. The worker queries the local LLM and returns:
- Most common attack types
- Primary targets
- Threat origins
- Bot vs. Human classification
- Expert executive summary

### Testing Attack Detection

All of the following are logged and appear in the Forensic Stream Analyzer.

**SQL Injection:**
```bash
curl -X POST http://localhost:8000/ \
  -d "username=admin' OR 1=1 --&password=password"
```

**Path Traversal:**
```bash
curl "http://localhost:8000/?file=../../../../etc/passwd"
```

**Brute Force:**
```bash
for i in $(seq 1 10); do
  curl -X POST http://localhost:8000/ -d "username=admin&password=pass$i"
done
```

**Scanner Detection:**
```bash
curl -A "sqlmap/1.4.11 (http://sqlmap.org)" http://localhost:8000/
curl -A "Nikto/2.1.6" http://localhost:8000/
curl -A "Mozilla/5.0 Hydra/9.1" http://localhost:8000/
```

---

## File Reference

| File | Purpose |
|---|---|
| `index.php` | Root entry — serves the bait login page |
| `gateway.php` | Bait login form; traps and logs all submissions |
| `staff_gate_7.php` | Hidden admin login portal |
| `command_hub_a1.php` | Analytics dashboard with charts, heatmap, AI insights |
| `stream_analyzer.php` | Forensic log viewer with filters, pagination, CSV export |
| `db.php` | Core: DB connection, geolocation, attack detection, CSRF, stats |
| `setup_db.php` | Database installer — creates schema, triggers, and seeds data |
| `schema.sql` | Standalone SQL schema (alternative to `setup_db.php`) |
| `logout.php` | Admin logout with session cleanup |
| `llm_insights.php` | JSON API endpoint for triggering/polling AI analysis |
| `llm_worker.php` | Background worker that queries Ollama |
| `rebuild_stats.php` | CLI tool to reclassify attack types and rebuild stats cache |
| `live_log_generator.php` | CLI traffic simulator |
| `.env` | Local environment variables (DB credentials) |
| `.env.example` | Template for `.env` |
| `install.lock` | Prevents re-running `setup_db.php` |

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---|---|---|
| `Database connection failed` | Wrong DB credentials in `.env` | Verify `DB_HOST`, `DB_USER`, `DB_PASS` match your MySQL setup |
| `SQLSTATE[HY000] [1045]` | MySQL user/password wrong | Run `mysql_secure_installation` or reset password |
| `SQLSTATE[HY000] [2002]` | MySQL not running or wrong host | `sudo systemctl start mysql`; check `DB_HOST=127.0.0.1` |
| `403 Forbidden` on admin pages | Not logged in | Visit `staff_gate_7.php` first |
| GeoIP shows "Unknown" for all IPs | ipapi.co rate limit or no outbound HTTPS | Check firewall; consider a local GeoIP database |
| Charts not rendering | No data or CDN blocked | Run `php live_log_generator.php seed`; check internet access |
| `pdo_mysql not found` | Missing PHP extension | Install `php-mysql` (Linux) or enable `extension=pdo_mysql` in `php.ini` |
| `install.lock` prevents re-setup | Already installed | Delete `install.lock` and re-run `php setup_db.php` |
| AI Insights stuck on "processing" | Ollama not running or no model | `ollama serve && ollama pull llama3.2:3b` |
| CSS/JS not loading | CDN inaccessible | Check internet or self-host the assets |
| Password "honey123" rejected | Setup already run with different password | Check `admin_accounts` table or delete `install.lock` and re-run setup |

---

## Security Notes

- **Change the default password** (`admin` / `honey123`) immediately after first login
- **Restrict access** to `staff_gate_7.php`, `command_hub_a1.php`, and `stream_analyzer.php` via firewall or `.htaccess` if possible
- **Run behind HTTPS** in production — session cookies and passwords are transmitted in plaintext over HTTP
- **The `.env` file** contains your database password — ensure it is NOT web-accessible (Apache blocks `.env` by default, but verify)
- **Geolocation API** (`ipapi.co`) has a free tier limit — for high-traffic deployments, use a local GeoIP database
- **CSV exports** may contain formula injection — be cautious opening exports in Excel
- **Self-host assets** if you want to prevent Referer header leakage to CDNs (Google Fonts, jsdelivr)

---

## License

MIT
