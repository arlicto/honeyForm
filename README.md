# 🍯 HoneyForm: Forensic Honeypot

HoneyForm is a professional-grade PHP/MySQL honeypot designed for high-fidelity attack simulation, real-time forensic logging, and interactive data visualization. It is built to deceive attackers with a convincing "dual-interface" architecture while providing security analysts with deep insights into malicious activity.

---

## ✨ Key Features

*   **🎭 Dual-Interface Architecture**: A high-fidelity "Bait" frontend to attract attackers, completely decoupled from the hidden "Staff Gate" admin portal.
*   **📊 Real-time Telemetry Dashboard**: Interactive visualizations using Chart.js, featuring attack trends, heatmaps, and top-N metrics.
*   **🧠 Automated Attack Classification**: Heuristic analysis engine that detects SQL Injection, Path Traversal, Brute Force, and Scanners.
*   **🌍 Intelligent Geolocation**: Automated IP-to-Country mapping for every attack attempt using external API integration and local caching.
*   **🛠️ Pen-test Tool Detection**: Specialized signatures to identify common security tools like `sqlmap`, `nikto`, `hydra`, and `nmap`.
*   **🔍 Forensic Stream Analyzer**: A dedicated tool for deep-diving into raw payloads, user agents, and historical attack patterns.
*   **🧠 Local LLM Forensic Insights**: Integrated background analysis using Ollama (Llama 3.2 3B) to provide concise, expert security summaries and attack attribution (Bot vs. Human).
*   **⚡ Live Traffic Simulator**: A CLI-based generator to populate the dashboard with realistic attack data for testing.

---

## 💻 Tech Stack

HoneyForm leverages a modern, lightweight tech stack for maximum performance and portability:

*   **Backend**: PHP 8.0+ (Vanilla with PDO for security)
*   **Database**: MySQL 5.7+ / MariaDB 10.3+
*   **Frontend**: HTML5, Vanilla JavaScript
*   **Styling**: Tailwind CSS (via CDN for rapid deployment)
*   **Visualization**: Chart.js 4.x
*   **Typography & Icons**: Google Fonts (Inter, JetBrains Mono) & Material Symbols
*   **APIs**: ipapi.co (Geolocation)
*   **AI/LLM**: Ollama (Running `llama3.2:3b` locally)

---

## 🛠️ Prerequisites

Before installing, ensure your environment meets the following requirements:

*   **PHP 8.0+** (Required extensions: `pdo_mysql`, `json`, `session`)
*   **MySQL 5.7+** or **MariaDB 10.3+**
*   **Web Server** (Apache, Nginx, or the built-in PHP server for testing)
*   **Ollama** (Optional, required for AI insights; must have `llama3.2:3b` pulled)
*   **Internet Access** (Required for loading Google Fonts, Chart.js, and Geolocation API lookups)

---

## 🖥️ Install & Enable (Ubuntu / Debian)

Run these commands to install PHP, the required extensions, MySQL and Apache, then enable/start services:

```bash
sudo apt update
sudo apt install -y php php-cli php-mysql php-xml php-json php-mbstring libapache2-mod-php mysql-server
sudo systemctl enable --now mysql
sudo systemctl enable --now apache2
sudo systemctl restart apache2
```

Verify the PDO MySQL extension is enabled:

```bash
php -m | grep -i pdo_mysql || echo "pdo_mysql not enabled"
```

## 🖥️ Install & Enable (macOS - Homebrew)

```bash
brew update
brew install php mysql
brew services start php
brew services start mysql
```

> Note: For Nginx + PHP-FPM, install `php-fpm` and configure your server to use the PHP-FPM socket; then start and enable the `php`/`php-fpm` service instead of `apache2`.

---


---

## 🚀 Installation Guide

### 1. Clone & Configure
First, clone the repository to your web server's root directory. Then, set up your environment variables:

```bash
cp .env.example .env
```

Open `.env` in your preferred editor and update the following values:
*   `DB_HOST`: Usually `127.0.0.1` or `localhost`
*   `DB_USER`: Your MySQL username
*   `DB_PASS`: Your MySQL password
*   `DB_NAME`: Defaults to `honeyform_db`

### 2. Automated Database Setup
HoneyForm includes an intelligent setup script that creates the database, defines the schema, and seeds it with default accounts. Run this from your terminal:

```bash
php setup_db.php
```

> [!IMPORTANT]
> This script creates an `install.lock` file to prevent accidental re-runs that would wipe your data. To re-initialize the database, delete `install.lock` first.

### 3. Start the Web Server
For development and presentation purposes, you can use PHP's built-in server:

```bash
php -S localhost:8000
```

---

## 🎭 Running the Honeypot

### 🛡️ Accessing the Analytics Dashboard
HoneyForm hides the real admin portal behind a "security through obscurity" gate.
1.  Navigate to: `http://localhost:8000/staff_gate_7.php`
2.  Log in with the default credentials:
    *   **Username**: `admin`
    *   **Password**: `honey123`
3.  You will be redirected to the **Command Hub (Dashboard)**.

### 🎣 The "Bait" (Attacker View)
The root page (`index.php` which routes to `gateway.php`) is designed to look like a sensitive administrative login.
*   **URL**: `http://localhost:8000/`
*   Any attempt to log in here is captured as an "attack" and logged with full forensic metadata (IP, User-Agent, Username, Password, Method).
*   Attackers receive a realistic "500 Internal Server Error" to maintain the illusion.

### ⚡ Live Presentation Mode (Log Generator)
If you are presenting HoneyForm and need to demonstrate real-time data updates without manual effort, use the included simulation script.

*   **Start Live Simulation** (Adds a new attack every 3 seconds by default):
    ```bash
    php live_log_generator.php [interval_seconds]
    ```
*   **Seed Historical Data** (Recommended for Demos):
    ```bash
    php live_log_generator.php seed
    ```
    *   Populates the database with **7 days** of randomized historical data. This ensures the line charts, heatmaps, and top-N lists are fully populated and dynamic instantly.
*   **Clear & Seed** (Best for a fresh presentation start):
    ```bash
    php live_log_generator.php clear seed
    ```
    *   Wipes all existing forensic data and then seeds 7 days of history before transitioning to live log generation.
*   **Clear Only** (Wipes database and exits):
    ```bash
    php live_log_generator.php clear-only
    ```

> [!TIP]
> The generator is flexible with arguments. You can use flags like `--seed`, `--clear`, or simply the keywords `seed`, `clear`, and `clear-only` in any order.

---

## 🧪 Testing Attack Detection

You can test the honeypot's detection engine using either the **Web Interface** (fake login page) for a realistic attacker experience, or `curl` for automated simulation. All attempts will immediately appear in the **Forensic Stream Analyzer**.

### 1. SQL Injection (SQLi)
Simulate an authentication bypass attempt using common SQL injection tokens.
*   **Web Interface**: Navigate to `http://localhost:8000/` and enter `' OR 1=1 --` in the **Admin Username** field.
*   **CLI (curl)**:
    ```bash
    curl -X POST http://localhost:8000/ -d "username=admin' OR 1=1 --&password=password"
    ```

### 2. Path Traversal
Attempt to access sensitive system files through directory traversal patterns.
*   **Browser**: Navigate to `http://localhost:8000/?file=../../../../etc/passwd`
*   **CLI (curl)**:
    ```bash
    curl "http://localhost:8000/gateway.php?file=../../../../etc/passwd"
    ```

### 3. Brute Force
Perform standard login attempts. Multiple attempts from the same IP will trigger alerts in the dashboard.
*   **Web Interface**: Try several random username/password combinations at `http://localhost:8000/`.
*   **CLI (curl)**:
    ```bash
    curl -X POST http://localhost:8000/ -d "username=root&password=password123"
    ```

### 4. Automated Scanners
Simulate a scan from a known pen-testing tool by modifying the `User-Agent` header. This is best tested via `curl`.
```bash
# Simulate sqlmap
curl -A "sqlmap/1.4.11 (http://sqlmap.org)" http://localhost:8000/

# Simulate Nikto
curl -A "Nikto/2.1.6" http://localhost:8000/
```

---

## 📂 Key Components

| File | Purpose |
| :--- | :--- |
| `gateway.php` | The primary bait; a fake login page that traps attackers. |
| `staff_gate_7.php` | The real, hidden login portal for administrators. |
| `command_hub_a1.php` | The main dashboard with real-time charts and telemetry. |
| `stream_analyzer.php` | Forensic tool for deep-diving into individual attack logs. |
| `live_log_generator.php` | CLI tool for simulating live attack traffic. |
| `db.php` | Core logic for database connectivity, security, and geolocation. |
| `llm_insights.php` | API endpoint for triggering and polling AI security analysis. |
| `llm_worker.php` | Background worker that communicates with Ollama for forensic insights. |



## 📝 Troubleshooting
*   **Database Connection Failed**: Double-check your `.env` credentials and ensure the MySQL service is running.
*   **Geolocation Not Working**: Ensure your server has outbound HTTPS access to `ipapi.co`.
*   **Missing Icons/Charts**: HoneyForm relies on CDN-hosted assets. Ensure you have a stable internet connection.
