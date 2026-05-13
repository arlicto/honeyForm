# 🍯 HoneyForm: Forensic Honeypot

HoneyForm is a high-fidelity PHP/MySQL honeypot designed to attract, log, and analyze cyberattacks in real-time. It features a stealthy "dual-interface" architecture to keep administrators hidden while engaging attackers with deceptive forensic data.

## 🚀 Quick Start (2-Minute Setup)

Follow these steps to get HoneyForm running on your local machine:

### 1. Configure the Environment
Clone the repository and create your configuration file:
```bash
cp .env.example .env
```
Open `.env` and enter your MySQL credentials (`DB_USER` and `DB_PASS`).

### 2. Initialize the Database
Run the automated setup script from your terminal. This creates the database, schema, and the default admin account:
```bash
php setup_db.php
```

### 3. Start the Server
You can use the built-in PHP development server:
```bash
php -S localhost:8000
```

---

## 🔍 How to Use

### 🎭 Attacker View (The Bait)
Go to: `http://localhost:8000`
This is the fake admin terminal. Any attempt to log in here is captured as an attack. Attackers will see a convincing "500 Internal Server Error" to keep them guessing.

### 🛡️ Admin View (The Intel)
Go to: `http://localhost:8000/staff_gate_7.php`
This is the **hidden** real admin login.
*   **Default Username**: `admin`
*   **Default Password**: `honey123`

---

## 🛠️ Requirements
*   **PHP 8.0+** (with `pdo_mysql` extension enabled)
*   **MySQL/MariaDB**
*   **Internet Connection** (Required for Geolocation API and UI assets)

---

## 📂 Project Structure
*   `gateway.php` — The high-fidelity fake login (Bait).
*   `staff_gate_7.php` — The real, hidden admin portal.
*   `command_hub_a1.php` — Real-time analytics dashboard.
*   `stream_analyzer.php` — Deep-dive forensic log viewer.
*   `db.php` — Core database and security logic.
