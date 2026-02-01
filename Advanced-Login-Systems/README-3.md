# Advanced Secure Login System (PHP)

A modern, secure, and extensible PHP authentication system featuring:

- Password hashing (bcrypt)
- IP-based brute-force protection
- Progressive account lockouts
- Security event logging
- Session fingerprinting
- CSRF protection
- SQLite (or MySQL/PostgreSQL) support

---

## Overview

This project demonstrates secure PHP login best practices using modern security techniques — ideal for web developers, cybersecurity students, or anyone learning secure authentication.

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/advanced-login-system.git
cd advanced-login-system

# Start a PHP Server
php -S localhost:8000

# Open in Browser
http://localhost:8000/

How to Use
Default Demo Login

Use these credentials to sign in:
Username	Password
demo	demo123

Creating a New User
Open the auth.db file in any SQLite editor (for example, DB Browser for SQLite).

Add a new record into the users table:
username: your chosen username
password_hash: generate with PHP:
<?php echo password_hash('yourpassword', PASSWORD_DEFAULT); ?>
Save the record.

You can now log in with your new credentials.
Lockout and Rate Limiting
After 5 failed login attempts, the IP is locked out for 5 minutes.
Further repeated failures extend the lockout:
10 attempts → 15 minutes
15 attempts → 1 hour
20 or more attempts → 24 hours

Lockout data is stored persistently in the SQLite rate_limits table.
Security Logs
All login events are written to security.log in JSON format, including:
Successful logins
Failed login attempts
Lockouts and CSRF violations
Logout events

# Session Protection
Each session is bound to a fingerprint (IP address + User-Agent + Session ID).
If a mismatch is detected, the session is destroyed and a new one is created.

# Configuration Options
You can modify several parameters directly in the code:
Lockout thresholds — in RateLimiter::calculateLockout()
Database engine — replace the sqlite: DSN with MySQL or PostgreSQL
Logging location — edit $logFile in SecurityLogger
CSRF token lifetime — can be rotated after each POST or per session

#Tips
Run PHP 8.0 or higher for compatibility.
Set file permissions properly (for example: chmod 600 auth.db security.log).
Always deploy behind HTTPS.
For production, consider adding reCAPTCHA or multi-factor authentication

# For Developers
You can extend this system by adding:
Password reset and email verification
Two-factor authentication (2FA)
Migration from SQLite to MySQL
JWT integration for API authentication

License
MIT License © 2025 Gresa Hisa
AI & ML Engineer & Cybersecurity Engineer 


