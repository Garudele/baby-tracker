<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — router.php  (multi-tenant)
// ============================================================================

// ---------- Cargar config ---------------------------------------------------
// __DIR__ = /home/uXXX/domains/site/public_html
$configPaths = [
    dirname(__DIR__, 3) . '/private/config.php',   // /home/uXXX/private/          ← recomendado
    dirname(__DIR__, 1) . '/private/config.php',   // /home/uXXX/domains/site/private/
    __DIR__ . '/config.php',                       // dev local (NO usar en prod)
];
$config = null;
foreach ($configPaths as $p) {
    if (file_exists($p)) { $config = require $p; break; }
}
if (!$config) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'config_missing', 'searched' => $configPaths]);
    exit;
}

// ---------- CORS ------------------------------------------------------------
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $config['allowed_origins'], true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Vary: Origin");
}
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ---------- Sesión ----------------------------------------------------------
session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'None',
]);
session_name('baby_sess');
session_start();

// ---------- Helpers ---------------------------------------------------------
function json_out($data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}
function json_body(): array {
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}
function db(): PDO {
    global $config;
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4",
            $config['db_user'],
            $config['db_pass'],
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );
    }
    return $pdo;
}
function require_auth(): void {
    if (empty($_SESSION['uid'])) json_out(['error' => 'unauthorized'], 401);
}
function client_ip(): string {
    return $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0';
}
function normalize_email(string $e): string {
    return strtolower(trim($e));
}
function is_valid_email(string $e): bool {
    return (bool)filter_var($e, FILTER_VALIDATE_EMAIL) && strlen($e) <= 255;
}

// ---------- Rate limiting ---------------------------------------------------
function record_attempt(string $action, bool $success, ?string $reason = null, ?string $email = null): void {
    $stmt = db()->prepare(
        "INSERT INTO auth_attempts (ip, email, success, reason, action)
         VALUES (:ip, :em, :ok, :r, :a)"
    );
    $stmt->execute([
        ':ip' => client_ip(),
        ':em' => $email,
        ':ok' => $success ? 1 : 0,
        ':r' => $reason,
        ':a' => $action,
    ]);
}
function is_ip_locked_out(string $action, int $max, int $window): bool {
    $stmt = db()->prepare(
        "SELECT COUNT(*) AS n FROM auth_attempts
         WHERE ip = :ip AND success = 0 AND action = :a
           AND attempted_at > (NOW() - INTERVAL :w SECOND)"
    );
    $stmt->execute([':ip' => client_ip(), ':a' => $action, ':w' => $window]);
    return (int)$stmt->fetch()['n'] >= $max;
}
function is_email_locked_out(string $email, int $max, int $window): bool {
    if ($email === '') return false;
    $stmt = db()->prepare(
        "SELECT COUNT(*) AS n FROM auth_attempts
         WHERE email = :em AND success = 0 AND action = 'login'
           AND attempted_at > (NOW() - INTERVAL :w SECOND)"
    );
    $stmt->execute([':em' => $email, ':w' => $window]);
    return (int)$stmt->fetch()['n'] >= $max;
}

// ---------- Crypto (AES-256-GCM para secretos en DB) ------------------------
function master_key(): string {
    global $config;
    $hex = $config['master_key_hex'] ?? '';
    if (strlen($hex) !== 64) throw new RuntimeException('master_key_hex must be 64 hex chars (32 bytes)');
    return hex2bin($hex);
}
function encrypt_secret(string $plain): string {
    $key = master_key();
    $nonce = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('encrypt failed');
    return $nonce . $tag . $ct;
}
function decrypt_secret(string $blob): string {
    $key = master_key();
    $nonce = substr($blob, 0, 12);
    $tag   = substr($blob, 12, 16);
    $ct    = substr($blob, 28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($pt === false) throw new RuntimeException('decrypt failed');
    return $pt;
}

// ---------- Router ----------------------------------------------------------
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';
$path = preg_replace('#^.*?/api/?#', '', $path);
$path = trim($path, '/');
$parts = $path === '' ? [] : explode('/', $path);
$method = $_SERVER['REQUEST_METHOD'];

// Config de rate limiting con defaults
$loginMax    = (int)($config['auth_max_attempts'] ?? 5);
$loginWindow = (int)($config['auth_lockout_window'] ?? 900);
$signupMax   = (int)($config['signup_max_per_day'] ?? 3);
$signupWindow= 86400; // 24h

try {
    // ---- Estado de sesión (sin auth) --------------------------------------
    if (($parts[0] ?? '') === 'me' && $method === 'GET') {
        $out = [
            'auth' => !empty($_SESSION['uid']),
            'features' => ['argon2id' => true, 'totp' => true, 'webauthn' => true, 'multi_tenant' => true],
        ];
        if (!empty($_SESSION['uid'])) {
            $s = db()->prepare("SELECT email, email_verified FROM users WHERE id = :u");
            $s->execute([':u' => $_SESSION['uid']]);
            if ($u = $s->fetch()) {
                $out['user'] = ['id' => (int)$_SESSION['uid'], 'email' => $u['email'], 'email_verified' => (bool)$u['email_verified']];
            }
        }
        json_out($out);
    }

    // ---- Signup (público) -------------------------------------------------
    if (($parts[0] ?? '') === 'signup' && $method === 'POST') {
        if (is_ip_locked_out('signup', $signupMax, $signupWindow)) {
            json_out(['error' => 'signup_rate_limited', 'retry_after' => $signupWindow], 429);
        }
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        $pw    = (string)($body['password'] ?? '');
        if (!is_valid_email($email)) {
            record_attempt('signup', false, 'bad_email', $email);
            json_out(['error' => 'bad_email'], 400);
        }
        if (strlen($pw) < 12) {
            record_attempt('signup', false, 'weak_password', $email);
            json_out(['error' => 'weak_password', 'min_length' => 12], 400);
        }
        try {
            $hash = password_hash($pw, PASSWORD_ARGON2ID);
            $stmt = db()->prepare(
                "INSERT INTO users (email, password_hash, email_verified) VALUES (:em, :h, 0)"
            );
            $stmt->execute([':em' => $email, ':h' => $hash]);
            $uid = (int)db()->lastInsertId();
        } catch (PDOException $e) {
            if ((int)$e->errorInfo[1] === 1062) { // duplicate key
                record_attempt('signup', false, 'email_taken', $email);
                json_out(['error' => 'email_taken'], 409);
            }
            throw $e;
        }
        record_attempt('signup', true, null, $email);
        // Auto-login tras signup
        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        json_out(['ok' => true, 'user' => ['id' => $uid, 'email' => $email]]);
    }

    // ---- Login (email + password) ----------------------------------------
    if (($parts[0] ?? '') === 'login' && $method === 'POST') {
        if (is_ip_locked_out('login', $loginMax, $loginWindow)) {
            json_out(['error' => 'locked_out', 'retry_after' => $loginWindow], 429);
        }
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        $pw    = (string)($body['password'] ?? '');

        if ($email !== '' && is_email_locked_out($email, $loginMax, $loginWindow)) {
            json_out(['error' => 'locked_out', 'retry_after' => $loginWindow], 429);
        }
        if (!is_valid_email($email) || $pw === '') {
            record_attempt('login', false, 'bad_input', $email);
            usleep(500000);
            json_out(['error' => 'bad_credentials'], 401);
        }
        $stmt = db()->prepare("SELECT id, password_hash, totp_enabled FROM users WHERE email = :em");
        $stmt->execute([':em' => $email]);
        $user = $stmt->fetch();
        if (!$user) {
            record_attempt('login', false, 'no_user', $email);
            usleep(500000);
            json_out(['error' => 'bad_credentials'], 401);
        }
        if (!password_verify($pw, $user['password_hash'])) {
            record_attempt('login', false, 'bad_password', $email);
            usleep(500000);
            json_out(['error' => 'bad_credentials'], 401);
        }
        if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($pw, PASSWORD_ARGON2ID);
            $up = db()->prepare("UPDATE users SET password_hash = :h WHERE id = :id");
            $up->execute([':h' => $newHash, ':id' => $user['id']]);
        }
        if ((int)$user['totp_enabled'] === 1) {
            $_SESSION['pending_totp_uid'] = (int)$user['id'];
            record_attempt('login', true, 'need_totp', $email);
            json_out(['ok' => true, 'need_totp' => true]);
        }
        session_regenerate_id(true);
        $_SESSION['uid'] = (int)$user['id'];
        record_attempt('login', true, null, $email);
        json_out(['ok' => true]);
    }

    // ---- Logout -----------------------------------------------------------
    if (($parts[0] ?? '') === 'logout' && $method === 'POST') {
        $_SESSION = [];
        session_destroy();
        json_out(['ok' => true]);
    }

    // A partir de aquí, requiere sesión
    require_auth();

    // ---- Datos (JSON blobs por key) --------------------------------------
    if (($parts[0] ?? '') === 'data' && $method === 'GET') {
        $stmt = db()->prepare("SELECT data_key, data_json FROM entries WHERE user_id = :u");
        $stmt->execute([':u' => $_SESSION['uid']]);
        $out = new stdClass();
        while ($row = $stmt->fetch()) {
            $out->{$row['data_key']} = json_decode($row['data_json'], true);
        }
        json_out($out);
    }
    if (($parts[0] ?? '') === 'data' && $method === 'PUT') {
        $body = json_body();
        $pdo = db();
        $pdo->beginTransaction();
        $stmt = $pdo->prepare(
            "INSERT INTO entries (user_id, data_key, data_json) VALUES (:u, :k, :v)
             ON DUPLICATE KEY UPDATE data_json = VALUES(data_json)"
        );
        $count = 0;
        foreach ($body as $key => $value) {
            $stmt->execute([':u' => $_SESSION['uid'], ':k' => $key, ':v' => json_encode($value)]);
            $count++;
        }
        $pdo->commit();
        json_out(['ok' => true, 'saved' => $count]);
    }

    // ---- Fotos ------------------------------------------------------------
    if (($parts[0] ?? '') === 'photos' && $method === 'GET') {
        $stmt = db()->prepare("SELECT id, record_type, record_id, mime, name FROM photos WHERE user_id = :u");
        $stmt->execute([':u' => $_SESSION['uid']]);
        json_out($stmt->fetchAll());
    }
    if (($parts[0] ?? '') === 'photo' && $method === 'POST') {
        $body = json_body();
        $id = (string)($body['id'] ?? bin2hex(random_bytes(16)));
        $mime = (string)($body['mime'] ?? 'image/jpeg');
        $recordType = isset($body['record_type']) ? (string)$body['record_type'] : null;
        $recordId = isset($body['record_id']) ? (int)$body['record_id'] : null;
        $name = isset($body['name']) ? (string)$body['name'] : null;
        $bin = base64_decode((string)($body['data'] ?? ''), true);
        if ($bin === false || $bin === '') json_out(['error' => 'bad_photo'], 400);
        $stmt = db()->prepare(
            "INSERT INTO photos (id, user_id, record_type, record_id, mime, name, data)
             VALUES (:id, :u, :rt, :ri, :mime, :name, :data)
             ON DUPLICATE KEY UPDATE mime = VALUES(mime), name = VALUES(name),
                                     record_type = VALUES(record_type), record_id = VALUES(record_id),
                                     data = VALUES(data)"
        );
        $stmt->bindValue(':id', $id);
        $stmt->bindValue(':u', $_SESSION['uid'], PDO::PARAM_INT);
        $stmt->bindValue(':rt', $recordType);
        $stmt->bindValue(':ri', $recordId, $recordId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':mime', $mime);
        $stmt->bindValue(':name', $name);
        $stmt->bindValue(':data', $bin, PDO::PARAM_LOB);
        $stmt->execute();
        json_out(['ok' => true, 'id' => $id]);
    }
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'GET') {
        $stmt = db()->prepare("SELECT mime, data FROM photos WHERE id = ? AND user_id = ?");
        $stmt->execute([$parts[1], $_SESSION['uid']]);
        $row = $stmt->fetch();
        if (!$row) json_out(['error' => 'not_found'], 404);
        header("Content-Type: {$row['mime']}");
        header('Cache-Control: private, max-age=31536000');
        echo $row['data'];
        exit;
    }
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'DELETE') {
        $stmt = db()->prepare("DELETE FROM photos WHERE id = ? AND user_id = ?");
        $stmt->execute([$parts[1], $_SESSION['uid']]);
        json_out(['ok' => true]);
    }

    json_out(['error' => 'not_found', 'path' => $path], 404);
} catch (Throwable $e) {
    json_out(['error' => 'server_error', 'detail' => $e->getMessage()], 500);
}
