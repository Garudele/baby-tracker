<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — router.php
// ============================================================================

// ---------- Diag temprano (no requiere config). BORRAR después de setup. ----
if (($_GET['t'] ?? '') === 'baby-diag-2026'
    && strpos($_SERVER['REQUEST_URI'] ?? '', '_diag') !== false) {
    header('Content-Type: text/plain; charset=utf-8');
    $algos = password_algos();
    $lines = [
        "PHP Version: " . PHP_VERSION,
        "SAPI: " . PHP_SAPI,
        "Argon2id: " . (in_array(PASSWORD_ARGON2ID, $algos, true) ? "SI" : "NO"),
        "openssl: " . (extension_loaded('openssl') ? "SI" : "NO"),
        "pdo_mysql: " . (extension_loaded('pdo_mysql') ? "SI" : "NO"),
        "config.php en private/: " . (file_exists(dirname(dirname(__DIR__)) . '/private/config.php') ? "SI" : "NO"),
        "config.php en public_html/: " . (file_exists(__DIR__ . '/config.php') ? "SI" : "NO"),
    ];
    echo implode("\n", $lines);
    exit;
}

// ---------- Cargar config ---------------------------------------------------
// Preferimos private/config.php (fuera de public_html). Fallback a ./config.php
// solo para dev local. El de public_html NO debería existir en producción.
// __DIR__ = /home/uXXX/domains/site/public_html
$configPaths = [
    dirname(__DIR__, 3) . '/private/config.php',   // /home/uXXX/private/          ← recomendado
    dirname(__DIR__, 1) . '/private/config.php',   // /home/uXXX/domains/site/private/
    __DIR__ . '/config.php',                       // dev local (NO usar en prod)
];
$config = null;
$configPath = null;
foreach ($configPaths as $p) {
    if (file_exists($p)) { $config = require $p; $configPath = $p; break; }
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

// ---------- Rate limiting ---------------------------------------------------
function record_attempt(bool $success, ?string $reason = null): void {
    $stmt = db()->prepare(
        "INSERT INTO auth_attempts (ip, success, reason) VALUES (:ip, :ok, :r)"
    );
    $stmt->execute([':ip' => client_ip(), ':ok' => $success ? 1 : 0, ':r' => $reason]);
}
function is_locked_out(): bool {
    global $config;
    $stmt = db()->prepare(
        "SELECT COUNT(*) AS n FROM auth_attempts
         WHERE ip = :ip AND success = 0
           AND attempted_at > (NOW() - INTERVAL :w SECOND)"
    );
    $stmt->execute([':ip' => client_ip(), ':w' => $config['auth_lockout_window']]);
    $n = (int)$stmt->fetch()['n'];
    return $n >= (int)$config['auth_max_attempts'];
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

try {
    // ---- Estado de sesión (sin auth) --------------------------------------
    if (($parts[0] ?? '') === 'me' && $method === 'GET') {
        json_out([
            'auth' => !empty($_SESSION['uid']),
            'features' => ['argon2id' => true, 'totp' => true, 'webauthn' => true],
        ]);
    }

    // ---- Login (password) -------------------------------------------------
    if (($parts[0] ?? '') === 'login' && $method === 'POST') {
        if (is_locked_out()) {
            json_out(['error' => 'locked_out', 'retry_after' => $config['auth_lockout_window']], 429);
        }
        $body = json_body();
        $pw = (string)($body['password'] ?? '');
        if ($pw === '') {
            record_attempt(false, 'empty_password');
            json_out(['error' => 'bad_password'], 401);
        }
        // Solo hay un usuario en esta app (id=1)
        $stmt = db()->prepare("SELECT id, password_hash, totp_enabled FROM users WHERE id = 1");
        $stmt->execute();
        $user = $stmt->fetch();
        if (!$user) {
            record_attempt(false, 'no_user');
            usleep(500000);
            json_out(['error' => 'not_installed'], 500);
        }
        if (!password_verify($pw, $user['password_hash'])) {
            record_attempt(false, 'bad_password');
            usleep(500000);
            json_out(['error' => 'bad_password'], 401);
        }
        // Re-hash si el algoritmo/params cambiaron
        if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($pw, PASSWORD_ARGON2ID);
            $up = db()->prepare("UPDATE users SET password_hash = :h WHERE id = :id");
            $up->execute([':h' => $newHash, ':id' => $user['id']]);
        }
        if ((int)$user['totp_enabled'] === 1) {
            // Password OK pero falta 2FA. Marcamos step 1 y pedimos código.
            $_SESSION['pending_totp_uid'] = (int)$user['id'];
            json_out(['ok' => true, 'need_totp' => true]);
        }
        // Sin 2FA: login completo
        session_regenerate_id(true);
        $_SESSION['uid'] = (int)$user['id'];
        record_attempt(true);
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
