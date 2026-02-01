<?php
/**
 * Advanced Login System with Comprehensive Security Features
 * 
 * Features:
 * - Database-backed authentication
 * - Password hashing with bcrypt
 * - IP-based rate limiting
 * - Session fingerprinting
 * - CSRF protection
 * - Security event logging
 * - Account lockout with progressive delays
 * - Brute force protection
 * 
 * @version 2.0.0
 * @license MIT
 */

class SecurityLogger {
    private $logFile;
    
    public function __construct($logFile = 'security.log') {
        $this->logFile = $logFile;
    }
    
    public function log($event, $details = []) {
        $entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'event' => $event,
            'details' => $details
        ];
        
        file_put_contents(
            $this->logFile,
            json_encode($entry) . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
    }
}

class RateLimiter {
    private $pdo;
    private $logger;
    
    public function __construct($pdo, $logger) {
        $this->pdo = $pdo;
        $this->logger = $logger;
        $this->initDatabase();
    }
    
    private function initDatabase() {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                attempt_count INTEGER DEFAULT 0,
                lockout_until INTEGER DEFAULT 0,
                last_attempt INTEGER,
                created_at INTEGER
            )
        ");
        
        $this->pdo->exec("
            CREATE INDEX IF NOT EXISTS idx_ip ON rate_limits(ip_address)
        ");
    }
    
    public function checkLimit($ip, $maxAttempts = 5, $windowSeconds = 900) {
        // Clean old records
        $this->pdo->exec("DELETE FROM rate_limits WHERE lockout_until < " . time() . " AND lockout_until > 0");
        
        $stmt = $this->pdo->prepare("SELECT * FROM rate_limits WHERE ip_address = ?");
        $stmt->execute([$ip]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$record) {
            return ['allowed' => true, 'attempts' => 0];
        }
        
        // Check if locked out
        if ($record['lockout_until'] > time()) {
            $remaining = ceil(($record['lockout_until'] - time()) / 60);
            return [
                'allowed' => false,
                'attempts' => $record['attempt_count'],
                'lockout_remaining' => $remaining
            ];
        }
        
        return ['allowed' => true, 'attempts' => $record['attempt_count']];
    }
    
    public function recordAttempt($ip, $success = false) {
        $stmt = $this->pdo->prepare("SELECT * FROM rate_limits WHERE ip_address = ?");
        $stmt->execute([$ip]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($success) {
            // Reset on successful login
            if ($record) {
                $this->pdo->prepare("DELETE FROM rate_limits WHERE ip_address = ?")->execute([$ip]);
            }
            return;
        }
        
        if (!$record) {
            // First failed attempt
            $stmt = $this->pdo->prepare("
                INSERT INTO rate_limits (ip_address, attempt_count, last_attempt, created_at)
                VALUES (?, 1, ?, ?)
            ");
            $stmt->execute([$ip, time(), time()]);
        } else {
            // Increment attempts
            $newCount = $record['attempt_count'] + 1;
            $lockoutTime = $this->calculateLockout($newCount);
            
            $stmt = $this->pdo->prepare("
                UPDATE rate_limits 
                SET attempt_count = ?, last_attempt = ?, lockout_until = ?
                WHERE ip_address = ?
            ");
            $stmt->execute([$newCount, time(), $lockoutTime, $ip]);
            
            if ($lockoutTime > time()) {
                $this->logger->log('account_locked', [
                    'attempts' => $newCount,
                    'lockout_minutes' => ceil(($lockoutTime - time()) / 60)
                ]);
            }
        }
    }
    
    private function calculateLockout($attempts) {
        // Progressive lockout: 5 min, 15 min, 1 hour, 24 hours
        $lockoutTimes = [
            5 => 300,      // 5 attempts = 5 minutes
            10 => 900,     // 10 attempts = 15 minutes
            15 => 3600,    // 15 attempts = 1 hour
            20 => 86400    // 20+ attempts = 24 hours
        ];
        
        foreach ($lockoutTimes as $threshold => $duration) {
            if ($attempts >= $threshold) {
                $lockout = $duration;
            }
        }
        
        return isset($lockout) ? time() + $lockout : 0;
    }
}

class AuthSystem {
    private $pdo;
    private $rateLimiter;
    private $logger;
    
    public function __construct($pdo, $rateLimiter, $logger) {
        $this->pdo = $pdo;
        $this->rateLimiter = $rateLimiter;
        $this->logger = $logger;
        $this->initDatabase();
    }
    
    private function initDatabase() {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at INTEGER,
                last_login INTEGER
            )
        ");
        
        // Create demo user (password: demo123)
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = 'demo'");
        $stmt->execute();
        if ($stmt->fetchColumn() == 0) {
            $hash = password_hash('demo123', PASSWORD_DEFAULT);
            $this->pdo->prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
                ->execute(['demo', $hash, time()]);
        }
    }
    
    public function login($username, $password, $ip) {
        // Check rate limit
        $limitCheck = $this->rateLimiter->checkLimit($ip);
        if (!$limitCheck['allowed']) {
            $this->logger->log('login_blocked', ['reason' => 'rate_limit']);
            return [
                'success' => false,
                'error' => 'Too many failed attempts. Account locked for ' . 
                          $limitCheck['lockout_remaining'] . ' minutes.'
            ];
        }
        
        // Verify credentials
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->rateLimiter->recordAttempt($ip, false);
            $this->logger->log('login_failed', ['username' => $username]);
            
            return [
                'success' => false,
                'error' => 'Invalid username or password.',
                'attempts' => $limitCheck['attempts'] + 1
            ];
        }
        
        // Success
        $this->rateLimiter->recordAttempt($ip, true);
        $this->logger->log('login_success', ['username' => $username]);
        
        // Update last login
        $this->pdo->prepare("UPDATE users SET last_login = ? WHERE id = ?")
            ->execute([time(), $user['id']]);
        
        return [
            'success' => true,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username']
            ]
        ];
    }
    
    public function createSessionFingerprint() {
        return hash('sha256', 
            $_SERVER['HTTP_USER_AGENT'] ?? '' .
            $_SERVER['REMOTE_ADDR'] ?? '' .
            session_id()
        );
    }
    
    public function validateSessionFingerprint($storedFingerprint) {
        return $storedFingerprint === $this->createSessionFingerprint();
    }
}

// Initialize system
session_start();

// Use SQLite for demo (switch to MySQL/PostgreSQL in production)
$pdo = new PDO('sqlite:auth.db');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$logger = new SecurityLogger();
$rateLimiter = new RateLimiter($pdo, $logger);
$auth = new AuthSystem($pdo, $rateLimiter, $logger);

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Session fingerprint validation
if (isset($_SESSION['fingerprint'])) {
    if (!$auth->validateSessionFingerprint($_SESSION['fingerprint'])) {
        session_destroy();
        session_start();
        $logger->log('session_hijack_attempt');
        $_SESSION['error'] = 'Session validation failed. Please login again.';
    }
}

$error = $_SESSION['error'] ?? '';
$success = $_SESSION['success'] ?? '';
unset($_SESSION['error'], $_SESSION['success']);

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $logger->log('csrf_violation');
        $error = 'Invalid request. Please try again.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $result = $auth->login($username, $password, $ip);
        
        if ($result['success']) {
            $_SESSION['user_id'] = $result['user']['id'];
            $_SESSION['username'] = $result['user']['username'];
            $_SESSION['fingerprint'] = $auth->createSessionFingerprint();
            $_SESSION['login_time'] = time();
            
            $success = 'Login successful! Welcome, ' . htmlspecialchars($result['user']['username']);
        } else {
            $error = $result['error'];
            if (isset($result['attempts'])) {
                $error .= ' (Attempt ' . $result['attempts'] . ')';
            }
        }
    }
    
    // Regenerate CSRF token
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Check if already logged in
$isLoggedIn = isset($_SESSION['user_id']) && isset($_SESSION['fingerprint']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Secure Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 450px;
        }
        
        h2 {
            color: #1e3c72;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.3s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #2a5298;
            box-shadow: 0 0 0 3px rgba(42, 82, 152, 0.1);
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(30, 60, 114, 0.4);
        }
        
        .btn-logout {
            background: linear-gradient(135deg, #c62828 0%, #e53935 100%);
        }
        
        .alert {
            padding: 14px 18px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            border-left: 4px solid;
        }
        
        .alert-error {
            background-color: #ffebee;
            border-color: #c62828;
            color: #c62828;
        }
        
        .alert-success {
            background-color: #e8f5e9;
            border-color: #2e7d32;
            color: #2e7d32;
        }
        
        .info-box {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 13px;
            color: #666;
        }
        
        .info-box strong {
            color: #333;
            display: block;
            margin-bottom: 5px;
        }
        
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #e8f5e9;
            color: #2e7d32;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .user-panel {
            text-align: center;
        }
        
        .user-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        
        .user-info {
            margin: 20px 0;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 8px;
        }
        
        .user-info p {
            margin: 8px 0;
            color: #666;
        }
        
        .user-info strong {
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($isLoggedIn): ?>
            <div class="user-panel">
                <div class="user-icon">👤</div>
                <h2>Welcome Back!</h2>
                <div class="user-info">
                    <p><strong>Username:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?></p>
                    <p><strong>Session Start:</strong> <?php echo date('Y-m-d H:i:s', $_SESSION['login_time']); ?></p>
                    <p><strong>IP Address:</strong> <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'unknown'); ?></p>
                </div>
                <form method="POST" action="?logout=1">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <button type="submit" class="btn btn-logout">Logout</button>
                </form>
            </div>
        <?php else: ?>
            <div class="security-badge">
                🔒 Multi-Layer Security Active
            </div>
            
            <h2>Secure Login</h2>
            <p class="subtitle">Advanced authentication system with comprehensive protection</p>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input 
                        type="text" 
                        name="username" 
                        id="username" 
                        required 
                        autocomplete="username"
                        placeholder="Enter your username"
                    />
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input 
                        type="password" 
                        name="password" 
                        id="password" 
                        required 
                        autocomplete="current-password"
                        placeholder="Enter your password"
                    />
                </div>
                
                <button type="submit" class="btn">Login Securely</button>
            </form>
            
            <div class="info-box">
                <strong>🎯 Demo Credentials:</strong>
                Username: <code>demo</code><br>
                Password: <code>demo123</code>
                
                <strong style="margin-top: 10px;">🛡️ Security Features:</strong>
                • IP-based rate limiting<br>
                • Progressive lockout delays<br>
                • CSRF protection<br>
                • Session fingerprinting<br>
                • Security event logging<br>
                • Bcrypt password hashing
            </div>
        <?php endif; ?>
    </div>
</body>
</html>

<?php
// Handle logout
if (isset($_GET['logout']) && $isLoggedIn) {
    $logger->log('logout', ['username' => $_SESSION['username']]);
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
?>