<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — router.php  (multi-tenant + babies + shares)
// ============================================================================

$configPaths = [
    dirname(__DIR__, 3) . '/private/config.php',
    dirname(__DIR__, 1) . '/private/config.php',
    __DIR__ . '/config.php',
];
$config = null;
foreach ($configPaths as $p) {
    if (file_exists($p)) { $config = require $p; break; }
}
if (!$config) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'config_missing']);
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
header("Access-Control-Allow-Headers: Content-Type, X-Baby-Id");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ---------- Sesión ----------------------------------------------------------
session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'None',
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
            $config['db_user'], $config['db_pass'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
        );
    }
    return $pdo;
}
function require_auth(): void {
    if (empty($_SESSION['uid'])) json_out(['error' => 'unauthorized'], 401);
}
function client_ip(): string {
    return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
function normalize_email(string $e): string { return strtolower(trim($e)); }
function is_valid_email(string $e): bool { return (bool)filter_var($e, FILTER_VALIDATE_EMAIL) && strlen($e) <= 255; }

// ---------- Rate limiting ---------------------------------------------------
function record_attempt(string $action, bool $success, ?string $reason = null, ?string $email = null): void {
    $stmt = db()->prepare("INSERT INTO auth_attempts (ip, email, success, reason, action) VALUES (:ip, :em, :ok, :r, :a)");
    $stmt->execute([':ip' => client_ip(), ':em' => $email, ':ok' => $success ? 1 : 0, ':r' => $reason, ':a' => $action]);
}
function is_ip_locked_out(string $action, int $max, int $window): bool {
    $stmt = db()->prepare("SELECT COUNT(*) AS n FROM auth_attempts WHERE ip = :ip AND success = 0 AND action = :a AND attempted_at > (NOW() - INTERVAL :w SECOND)");
    $stmt->execute([':ip' => client_ip(), ':a' => $action, ':w' => $window]);
    return (int)$stmt->fetch()['n'] >= $max;
}
function is_email_locked_out(string $email, int $max, int $window): bool {
    if ($email === '') return false;
    $stmt = db()->prepare("SELECT COUNT(*) AS n FROM auth_attempts WHERE email = :em AND success = 0 AND action = 'login' AND attempted_at > (NOW() - INTERVAL :w SECOND)");
    $stmt->execute([':em' => $email, ':w' => $window]);
    return (int)$stmt->fetch()['n'] >= $max;
}

// ---------- Crypto (AES-256-GCM) --------------------------------------------
function master_key(): string {
    global $config;
    $hex = $config['master_key_hex'] ?? '';
    if (strlen($hex) !== 64) throw new RuntimeException('master_key_hex must be 64 hex chars');
    return hex2bin($hex);
}
function encrypt_secret(string $plain): string {
    $key = master_key(); $nonce = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('encrypt failed');
    return $nonce . $tag . $ct;
}
function decrypt_secret(string $blob): string {
    $key = master_key();
    $nonce = substr($blob, 0, 12); $tag = substr($blob, 12, 16); $ct = substr($blob, 28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($pt === false) throw new RuntimeException('decrypt failed');
    return $pt;
}

// ---------- Email sending ---------------------------------------------------
function send_email(string $to, string $subject, string $bodyHtml, string $bodyText): bool {
    global $config;
    $from = $config['mail_from'] ?? ('no-reply@' . ($config['webauthn_rp_id'] ?? 'baby.angaes.com'));
    $fromName = $config['mail_from_name'] ?? 'Baby Tracker';
    $boundary = 'bnd_' . bin2hex(random_bytes(8));
    $headers = "From: $fromName <$from>\r\n";
    $headers .= "Reply-To: $from\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";
    $body  = "--$boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n$bodyText\r\n\r\n";
    $body .= "--$boundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n$bodyHtml\r\n\r\n";
    $body .= "--$boundary--";
    return @mail($to, $subject, $body, $headers, '-f' . $from);
}

// ---------- TOTP (RFC 6238) -------------------------------------------------
function base32_encode(string $bin): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for ($i = 0; $i < strlen($bin); $i++) {
        $bits .= str_pad(decbin(ord($bin[$i])), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $out .= $alphabet[bindec($chunk)];
    }
    return $out;
}
function base32_decode(string $s): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = strtoupper(preg_replace('/[^A-Z2-7]/', '', $s));
    $bits = '';
    for ($i = 0; $i < strlen($s); $i++) {
        $pos = strpos($alphabet, $s[$i]);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) $out .= chr(bindec($chunk));
    }
    return $out;
}
function totp_generate(string $secret, ?int $time = null): string {
    $time = $time ?? time();
    $counter = intdiv($time, 30);
    $binCounter = pack('J', $counter);
    $hash = hash_hmac('sha1', $binCounter, $secret, true);
    $offset = ord($hash[19]) & 0x0f;
    $code = (
        ((ord($hash[$offset]) & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) << 8) |
        (ord($hash[$offset + 3]) & 0xff)
    ) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}
function totp_verify(string $secret, string $code, int $window = 1): bool {
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) return false;
    $now = time();
    for ($w = -$window; $w <= $window; $w++) {
        if (hash_equals(totp_generate($secret, $now + $w * 30), $code)) return true;
    }
    return false;
}
function totp_uri(string $secretB32, string $email, string $issuer = 'Baby Tracker'): string {
    return 'otpauth://totp/' . rawurlencode($issuer . ':' . $email)
        . '?secret=' . $secretB32
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}

// ---------- Babies helpers --------------------------------------------------
function list_user_babies(int $uid): array {
    // Bebés propios + compartidos (aceptados)
    $stmt = db()->prepare("
        SELECT b.*, 'owner' AS role, NULL AS shared_by
          FROM babies b WHERE b.owner_id = :u
        UNION ALL
        SELECT b.*, s.role AS role, b.owner_id AS shared_by
          FROM babies b
          JOIN baby_shares s ON s.baby_id = b.id
         WHERE s.user_id = :u AND s.accepted_at IS NOT NULL
         ORDER BY name
    ");
    $stmt->execute([':u' => $uid]);
    return $stmt->fetchAll();
}
function baby_access(int $uid, int $babyId): ?array {
    // Devuelve ['role' => owner|editor|viewer|admin] o null si sin acceso
    $stmt = db()->prepare("SELECT owner_id FROM babies WHERE id = ?");
    $stmt->execute([$babyId]);
    $row = $stmt->fetch();
    if (!$row) return null;
    if ((int)$row['owner_id'] === $uid) return ['role' => 'owner'];
    $s = db()->prepare("SELECT role FROM baby_shares WHERE baby_id = ? AND user_id = ? AND accepted_at IS NOT NULL");
    $s->execute([$babyId, $uid]);
    $sh = $s->fetch();
    return $sh ? ['role' => $sh['role']] : null;
}
function resolved_baby_id(int $uid, ?string $override = null): int {
    // Order: explicit param → session current → user's first baby
    if ($override && ctype_digit($override)) {
        $bid = (int)$override;
        if (baby_access($uid, $bid)) {
            $_SESSION['baby_id'] = $bid;
            return $bid;
        }
        json_out(['error' => 'no_access_to_baby'], 403);
    }
    if (!empty($_SESSION['baby_id']) && baby_access($uid, (int)$_SESSION['baby_id'])) {
        return (int)$_SESSION['baby_id'];
    }
    $stmt = db()->prepare("SELECT id FROM babies WHERE owner_id = ? ORDER BY id LIMIT 1");
    $stmt->execute([$uid]);
    $row = $stmt->fetch();
    if ($row) {
        $_SESSION['baby_id'] = (int)$row['id'];
        return (int)$row['id'];
    }
    json_out(['error' => 'no_babies', 'message' => 'Crea un bebé primero'], 400);
}
function get_baby_id_from_request(): ?string {
    return $_GET['baby'] ?? $_SERVER['HTTP_X_BABY_ID'] ?? null;
}

// ---------- Router ----------------------------------------------------------
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';
$path = preg_replace('#^.*?/api/?#', '', $path);
$path = trim($path, '/');
$parts = $path === '' ? [] : explode('/', $path);
$method = $_SERVER['REQUEST_METHOD'];

$loginMax    = (int)($config['auth_max_attempts'] ?? 5);
$loginWindow = (int)($config['auth_lockout_window'] ?? 900);
$signupMax   = (int)($config['signup_max_per_day'] ?? 3);
$signupWindow = 86400;

try {
    // ---- Estado sesión + user + babies -----------------------------------
    if (($parts[0] ?? '') === 'me' && $method === 'GET') {
        $out = [
            'auth' => !empty($_SESSION['uid']),
            'features' => ['argon2id' => true, 'totp' => true, 'webauthn' => true, 'multi_tenant' => true, 'babies' => true],
        ];
        if (!empty($_SESSION['uid'])) {
            $uid = (int)$_SESSION['uid'];
            $s = db()->prepare("SELECT email, email_verified, totp_enabled FROM users WHERE id = :u");
            $s->execute([':u' => $uid]);
            if ($u = $s->fetch()) {
                $out['user'] = ['id' => $uid, 'email' => $u['email'], 'email_verified' => (bool)$u['email_verified'], 'totp_enabled' => (bool)$u['totp_enabled']];
            }
            $out['babies'] = list_user_babies($uid);
            $out['active_baby_id'] = $_SESSION['baby_id'] ?? ($out['babies'][0]['id'] ?? null);
        }
        json_out($out);
    }

    // ---- Signup ----------------------------------------------------------
    if (($parts[0] ?? '') === 'signup' && $method === 'POST') {
        if (is_ip_locked_out('signup', $signupMax, $signupWindow)) json_out(['error' => 'signup_rate_limited', 'retry_after' => $signupWindow], 429);
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        $pw    = (string)($body['password'] ?? '');
        if (!is_valid_email($email)) { record_attempt('signup', false, 'bad_email', $email); json_out(['error' => 'bad_email'], 400); }
        if (strlen($pw) < 12) { record_attempt('signup', false, 'weak_password', $email); json_out(['error' => 'weak_password', 'min_length' => 12], 400); }
        try {
            $hash = password_hash($pw, PASSWORD_ARGON2ID);
            $stmt = db()->prepare("INSERT INTO users (email, password_hash, email_verified) VALUES (:em, :h, 0)");
            $stmt->execute([':em' => $email, ':h' => $hash]);
            $uid = (int)db()->lastInsertId();
        } catch (PDOException $e) {
            if ((int)$e->errorInfo[1] === 1062) { record_attempt('signup', false, 'email_taken', $email); json_out(['error' => 'email_taken'], 409); }
            throw $e;
        }
        record_attempt('signup', true, null, $email);
        // Auto-crear bebé default
        $ins = db()->prepare("INSERT INTO babies (owner_id, name, emoji) VALUES (?, 'Mi bebé', '👶')");
        $ins->execute([$uid]);
        $bid = (int)db()->lastInsertId();
        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        $_SESSION['baby_id'] = $bid;
        json_out(['ok' => true, 'user' => ['id' => $uid, 'email' => $email], 'baby_id' => $bid]);
    }

    // ---- Login -----------------------------------------------------------
    if (($parts[0] ?? '') === 'login' && $method === 'POST') {
        if (is_ip_locked_out('login', $loginMax, $loginWindow)) json_out(['error' => 'locked_out', 'retry_after' => $loginWindow], 429);
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        $pw    = (string)($body['password'] ?? '');
        if ($email !== '' && is_email_locked_out($email, $loginMax, $loginWindow)) json_out(['error' => 'locked_out', 'retry_after' => $loginWindow], 429);
        if (!is_valid_email($email) || $pw === '') { record_attempt('login', false, 'bad_input', $email); usleep(500000); json_out(['error' => 'bad_credentials'], 401); }
        $stmt = db()->prepare("SELECT id, password_hash, totp_enabled FROM users WHERE email = :em");
        $stmt->execute([':em' => $email]);
        $user = $stmt->fetch();
        if (!$user) { record_attempt('login', false, 'no_user', $email); usleep(500000); json_out(['error' => 'bad_credentials'], 401); }
        if (!password_verify($pw, $user['password_hash'])) { record_attempt('login', false, 'bad_password', $email); usleep(500000); json_out(['error' => 'bad_credentials'], 401); }
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
        // Auto-crear bebé default si el usuario no tiene ninguno
        $chk = db()->prepare("SELECT id FROM babies WHERE owner_id = ? LIMIT 1");
        $chk->execute([(int)$user['id']]);
        if (!$chk->fetch()) {
            $ins = db()->prepare("INSERT INTO babies (owner_id, name, emoji) VALUES (?, 'Mi bebé', '👶')");
            $ins->execute([(int)$user['id']]);
            $_SESSION['baby_id'] = (int)db()->lastInsertId();
        }
        record_attempt('login', true, null, $email);
        json_out(['ok' => true]);
    }

    // ---- Login 2do paso: TOTP -------------------------------------------
    if (($parts[0] ?? '') === 'login' && ($parts[1] ?? '') === 'totp' && $method === 'POST') {
        if (empty($_SESSION['pending_totp_uid'])) json_out(['error' => 'no_pending_login'], 400);
        $uid = (int)$_SESSION['pending_totp_uid'];
        $body = json_body();
        $code = (string)($body['code'] ?? '');
        $stmt = db()->prepare("SELECT totp_secret_encrypted FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u || !$u['totp_secret_encrypted']) json_out(['error' => 'no_totp_setup'], 400);
        try {
            $secret = decrypt_secret($u['totp_secret_encrypted']);
        } catch (Throwable $e) {
            json_out(['error' => 'decrypt_failed'], 500);
        }
        if (!totp_verify($secret, $code)) {
            record_attempt('login_totp', false, 'bad_totp', null);
            usleep(500000);
            json_out(['error' => 'bad_code'], 401);
        }
        unset($_SESSION['pending_totp_uid']);
        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        // Auto-crear bebé si no tiene
        $chk = db()->prepare("SELECT id FROM babies WHERE owner_id = ? LIMIT 1");
        $chk->execute([$uid]);
        if (!$chk->fetch()) {
            $ins = db()->prepare("INSERT INTO babies (owner_id, name, emoji) VALUES (?, 'Mi bebé', '👶')");
            $ins->execute([$uid]);
            $_SESSION['baby_id'] = (int)db()->lastInsertId();
        }
        record_attempt('login_totp', true);
        json_out(['ok' => true]);
    }

    // ---- WebAuthn passkey login (sin auth previa) -----------------------
    if (($parts[0] ?? '') === 'passkey' && ($parts[1] ?? '') === 'auth' && ($parts[2] ?? '') === 'start' && $method === 'POST') {
        require_once __DIR__ . '/webauthn/WebAuthn.php';
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        if (!is_valid_email($email)) json_out(['error' => 'bad_email'], 400);
        $u = db()->prepare("SELECT id FROM users WHERE email = ?");
        $u->execute([$email]);
        $user = $u->fetch();
        if (!$user) {
            usleep(500000);
            json_out(['error' => 'no_credentials'], 404);
        }
        $c = db()->prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = ?");
        $c->execute([$user['id']]);
        $creds = [];
        foreach ($c->fetchAll() as $r) $creds[] = $r['credential_id'];
        if (!$creds) json_out(['error' => 'no_credentials'], 404);
        $wa = new \lbuchs\WebAuthn\WebAuthn($config['webauthn_rp_name'], $config['webauthn_rp_id']);
        $args = $wa->getGetArgs($creds, 60 * 2, true, true, true, true, 'discouraged');
        $_SESSION['wa_auth_challenge'] = $wa->getChallenge()->getBinaryString();
        $_SESSION['wa_auth_uid'] = (int)$user['id'];
        json_out($args);
    }
    if (($parts[0] ?? '') === 'passkey' && ($parts[1] ?? '') === 'auth' && ($parts[2] ?? '') === 'finish' && $method === 'POST') {
        require_once __DIR__ . '/webauthn/WebAuthn.php';
        if (empty($_SESSION['wa_auth_challenge']) || empty($_SESSION['wa_auth_uid'])) json_out(['error' => 'no_challenge'], 400);
        $body = json_body();
        $uid = (int)$_SESSION['wa_auth_uid'];
        $wa = new \lbuchs\WebAuthn\WebAuthn($config['webauthn_rp_name'], $config['webauthn_rp_id']);
        $challenge = new \lbuchs\WebAuthn\Binary\ByteBuffer($_SESSION['wa_auth_challenge']);
        $credentialId = base64_decode($body['credentialId'] ?? '');
        // Buscar la credential
        $c = db()->prepare("SELECT id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?");
        $c->bindValue(1, $uid, PDO::PARAM_INT);
        $c->bindValue(2, $credentialId, PDO::PARAM_LOB);
        $c->execute();
        $cred = $c->fetch();
        if (!$cred) json_out(['error' => 'unknown_credential'], 400);
        try {
            $wa->processGet(
                base64_decode($body['clientDataJSON'] ?? ''),
                base64_decode($body['authenticatorData'] ?? ''),
                base64_decode($body['signature'] ?? ''),
                $cred['public_key'],
                $challenge,
                (int)$cred['sign_count'],
                true,
                false
            );
        } catch (Throwable $e) {
            record_attempt('passkey_login', false, 'bad_assertion');
            json_out(['error' => 'assertion_failed', 'detail' => $e->getMessage()], 401);
        }
        // Actualizar last_used + sign_count
        db()->prepare("UPDATE webauthn_credentials SET sign_count = sign_count + 1, last_used_at = NOW() WHERE id = ?")->execute([$cred['id']]);
        unset($_SESSION['wa_auth_challenge'], $_SESSION['wa_auth_uid']);
        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        // Auto-crear bebé si no tiene
        $chk = db()->prepare("SELECT id FROM babies WHERE owner_id = ? LIMIT 1");
        $chk->execute([$uid]);
        if (!$chk->fetch()) {
            $ins = db()->prepare("INSERT INTO babies (owner_id, name, emoji) VALUES (?, 'Mi bebé', '👶')");
            $ins->execute([$uid]);
            $_SESSION['baby_id'] = (int)db()->lastInsertId();
        }
        record_attempt('passkey_login', true);
        json_out(['ok' => true]);
    }

    // ---- Password reset request (público) -------------------------------
    if (($parts[0] ?? '') === 'password' && ($parts[1] ?? '') === 'reset' && ($parts[2] ?? '') === 'request' && $method === 'POST') {
        if (is_ip_locked_out('reset', 5, 3600)) json_out(['error' => 'rate_limited'], 429);
        $body = json_body();
        $email = normalize_email((string)($body['email'] ?? ''));
        if (!is_valid_email($email)) { record_attempt('reset', false, 'bad_email', $email); json_out(['error' => 'bad_email'], 400); }
        $stmt = db()->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $u = $stmt->fetch();
        // Siempre 200 (evita user enumeration)
        if ($u) {
            $token = bin2hex(random_bytes(32));
            $ins = db()->prepare("INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))");
            $ins->execute([$token, $u['id']]);
            $link = 'https://' . ($_SERVER['HTTP_HOST'] ?? $config['webauthn_rp_id']) . '/?reset=' . $token;
            $html = "<p>Hola,</p><p>Recibimos una solicitud para restablecer tu contraseña de Baby Tracker.</p>"
                . "<p><a href=\"$link\">Click aquí para elegir una nueva contraseña</a></p>"
                . "<p>El link expira en 1 hora. Si no fuiste tú, ignora este correo.</p>";
            $text = "Reset de contraseña Baby Tracker:\n$link\n\nExpira en 1 hora. Ignora si no fuiste tú.";
            send_email($email, 'Baby Tracker — Reset de contraseña', $html, $text);
            record_attempt('reset', true, null, $email);
        } else {
            record_attempt('reset', false, 'no_user', $email);
        }
        json_out(['ok' => true, 'message' => 'Si el email existe, recibirás instrucciones.']);
    }

    // ---- Password reset confirm (público) -------------------------------
    if (($parts[0] ?? '') === 'password' && ($parts[1] ?? '') === 'reset' && ($parts[2] ?? '') === 'confirm' && $method === 'POST') {
        $body = json_body();
        $token = (string)($body['token'] ?? '');
        $newPw = (string)($body['password'] ?? '');
        if (strlen($newPw) < 12) json_out(['error' => 'weak_password'], 400);
        $stmt = db()->prepare("SELECT user_id FROM password_resets WHERE token = ? AND used_at IS NULL AND expires_at > NOW()");
        $stmt->execute([$token]);
        $r = $stmt->fetch();
        if (!$r) json_out(['error' => 'invalid_or_expired'], 400);
        $hash = password_hash($newPw, PASSWORD_ARGON2ID);
        $pdo = db();
        $pdo->beginTransaction();
        $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$hash, $r['user_id']]);
        $pdo->prepare("UPDATE password_resets SET used_at = NOW() WHERE token = ?")->execute([$token]);
        $pdo->commit();
        json_out(['ok' => true]);
    }

    // ---- Info pública de invitación (sin auth) --------------------------
    if (($parts[0] ?? '') === 'invitations' && isset($parts[1]) && !isset($parts[2]) && $method === 'GET') {
        $stmt = db()->prepare("SELECT i.baby_id, i.role, i.invitee_email, i.expires_at, b.name AS baby_name, b.emoji AS baby_emoji, u.email AS inviter_email FROM invitations i JOIN babies b ON b.id = i.baby_id JOIN users u ON u.id = i.inviter_id WHERE i.token = ? AND i.accepted_at IS NULL AND i.expires_at > NOW()");
        $stmt->execute([$parts[1]]);
        $row = $stmt->fetch();
        if (!$row) json_out(['error' => 'invalid_or_expired'], 404);
        json_out([
            'baby_name' => $row['baby_name'],
            'baby_emoji' => $row['baby_emoji'],
            'role' => $row['role'],
            'invitee_email' => $row['invitee_email'],
            'inviter_email' => $row['inviter_email'],
            'expires_at' => $row['expires_at'],
        ]);
    }

    // ---- Logout ----------------------------------------------------------
    if (($parts[0] ?? '') === 'logout' && $method === 'POST') {
        $_SESSION = [];
        session_destroy();
        json_out(['ok' => true]);
    }

    require_auth();
    $uid = (int)$_SESSION['uid'];

    // ---- 2FA management -------------------------------------------------
    if (($parts[0] ?? '') === '2fa' && ($parts[1] ?? '') === 'setup' && $method === 'POST') {
        // Genera un nuevo secreto TENTATIVO (aún no activo)
        $secret = random_bytes(20);
        $secretB32 = base32_encode($secret);
        $_SESSION['pending_totp_secret_b32'] = $secretB32;
        $stmt = db()->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        $email = $u['email'] ?? 'user';
        json_out([
            'ok' => true,
            'secret' => $secretB32,
            'uri' => totp_uri($secretB32, $email),
        ]);
    }
    if (($parts[0] ?? '') === '2fa' && ($parts[1] ?? '') === 'enable' && $method === 'POST') {
        if (empty($_SESSION['pending_totp_secret_b32'])) json_out(['error' => 'no_pending_setup'], 400);
        $body = json_body();
        $code = (string)($body['code'] ?? '');
        $secret = base32_decode($_SESSION['pending_totp_secret_b32']);
        if (!totp_verify($secret, $code)) json_out(['error' => 'bad_code'], 400);
        $enc = encrypt_secret($secret);
        $up = db()->prepare("UPDATE users SET totp_secret_encrypted = :s, totp_enabled = 1 WHERE id = :u");
        $up->bindValue(':s', $enc, PDO::PARAM_LOB);
        $up->bindValue(':u', $uid, PDO::PARAM_INT);
        $up->execute();
        unset($_SESSION['pending_totp_secret_b32']);
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === '2fa' && ($parts[1] ?? '') === 'disable' && $method === 'POST') {
        $body = json_body();
        // Requerir password para desactivar 2FA
        $pw = (string)($body['password'] ?? '');
        $stmt = db()->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u || !password_verify($pw, $u['password_hash'])) json_out(['error' => 'bad_password'], 401);
        $up = db()->prepare("UPDATE users SET totp_secret_encrypted = NULL, totp_enabled = 0 WHERE id = ?");
        $up->execute([$uid]);
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === '2fa' && ($parts[1] ?? '') === 'status' && $method === 'GET') {
        $stmt = db()->prepare("SELECT totp_enabled FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        json_out(['enabled' => (bool)($u['totp_enabled'] ?? 0)]);
    }

    // ---- Cambiar contraseña ---------------------------------------------
    if (($parts[0] ?? '') === 'password' && ($parts[1] ?? '') === 'change' && $method === 'POST') {
        $body = json_body();
        $oldPw = (string)($body['old_password'] ?? '');
        $newPw = (string)($body['new_password'] ?? '');
        if (strlen($newPw) < 12) json_out(['error' => 'weak_password'], 400);
        $stmt = db()->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u || !password_verify($oldPw, $u['password_hash'])) json_out(['error' => 'bad_password'], 401);
        $hash = password_hash($newPw, PASSWORD_ARGON2ID);
        db()->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$hash, $uid]);
        json_out(['ok' => true]);
    }

    // ---- Verificar email ------------------------------------------------
    if (($parts[0] ?? '') === 'email' && ($parts[1] ?? '') === 'send_verification' && $method === 'POST') {
        $stmt = db()->prepare("SELECT email, email_verified FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u) json_out(['error' => 'no_user'], 404);
        if ((int)$u['email_verified']) json_out(['ok' => true, 'already_verified' => true]);
        $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        db()->prepare("REPLACE INTO email_verifications (user_id, code, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))")->execute([$uid, $code]);
        $html = "<p>Tu código de verificación de Baby Tracker es:</p>"
            . "<h2 style=\"font-family:monospace;letter-spacing:0.3em;text-align:center\">$code</h2>"
            . "<p>Expira en 15 minutos.</p>";
        $text = "Código de verificación Baby Tracker: $code (expira en 15 min)";
        send_email($u['email'], 'Baby Tracker — Verifica tu email', $html, $text);
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === 'email' && ($parts[1] ?? '') === 'verify' && $method === 'POST') {
        $body = json_body();
        $code = trim((string)($body['code'] ?? ''));
        if (!preg_match('/^\d{6}$/', $code)) json_out(['error' => 'bad_code'], 400);
        $stmt = db()->prepare("SELECT code FROM email_verifications WHERE user_id = ? AND expires_at > NOW()");
        $stmt->execute([$uid]);
        $v = $stmt->fetch();
        if (!$v || !hash_equals($v['code'], $code)) json_out(['error' => 'bad_code'], 400);
        $pdo = db();
        $pdo->beginTransaction();
        $pdo->prepare("UPDATE users SET email_verified = 1 WHERE id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM email_verifications WHERE user_id = ?")->execute([$uid]);
        $pdo->commit();
        json_out(['ok' => true]);
    }

    // ---- Delete account -------------------------------------------------
    if (($parts[0] ?? '') === 'account' && $method === 'DELETE') {
        $body = json_body();
        $pw = (string)($body['password'] ?? '');
        $stmt = db()->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u || !password_verify($pw, $u['password_hash'])) json_out(['error' => 'bad_password'], 401);
        // Borrar todo lo del usuario (cascade manual)
        $pdo = db();
        $pdo->beginTransaction();
        // Bebés propios y sus datos
        $bs = $pdo->prepare("SELECT id FROM babies WHERE owner_id = ?");
        $bs->execute([$uid]);
        foreach ($bs->fetchAll() as $b) {
            $bid = (int)$b['id'];
            $pdo->prepare("DELETE FROM entries WHERE baby_id = ?")->execute([$bid]);
            $pdo->prepare("DELETE FROM photos WHERE baby_id = ?")->execute([$bid]);
            $pdo->prepare("DELETE FROM baby_shares WHERE baby_id = ?")->execute([$bid]);
            $pdo->prepare("DELETE FROM invitations WHERE baby_id = ?")->execute([$bid]);
        }
        $pdo->prepare("DELETE FROM babies WHERE owner_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM baby_shares WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM webauthn_credentials WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM email_verifications WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM password_resets WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$uid]);
        $pdo->commit();
        $_SESSION = [];
        session_destroy();
        json_out(['ok' => true]);
    }

    // ---- WebAuthn / Passkey management ----------------------------------
    if (($parts[0] ?? '') === 'passkey' && !isset($parts[1]) && $method === 'GET') {
        $stmt = db()->prepare("SELECT id, device_name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY id DESC");
        $stmt->execute([$uid]);
        json_out($stmt->fetchAll());
    }
    if (($parts[0] ?? '') === 'passkey' && isset($parts[1]) && ctype_digit($parts[1]) && $method === 'DELETE') {
        $cid = (int)$parts[1];
        db()->prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")->execute([$cid, $uid]);
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === 'passkey' && ($parts[1] ?? '') === 'register' && ($parts[2] ?? '') === 'start' && $method === 'POST') {
        require_once __DIR__ . '/webauthn/WebAuthn.php';
        $u = db()->prepare("SELECT email FROM users WHERE id = ?");
        $u->execute([$uid]);
        $urow = $u->fetch();
        $wa = new \lbuchs\WebAuthn\WebAuthn($config['webauthn_rp_name'], $config['webauthn_rp_id']);
        // Excluir credenciales ya registradas
        $ex = db()->prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = ?");
        $ex->execute([$uid]);
        $excluded = [];
        foreach ($ex->fetchAll() as $r) $excluded[] = $r['credential_id'];
        $args = $wa->getCreateArgs(
            (string)$uid, $urow['email'], $urow['email'],
            60 * 4, // timeout 4min
            'discouraged', // userVerification
            null, // requireResidentKey
            $excluded
        );
        $_SESSION['wa_challenge'] = $wa->getChallenge()->getBinaryString();
        json_out($args);
    }
    if (($parts[0] ?? '') === 'passkey' && ($parts[1] ?? '') === 'register' && ($parts[2] ?? '') === 'finish' && $method === 'POST') {
        require_once __DIR__ . '/webauthn/WebAuthn.php';
        if (empty($_SESSION['wa_challenge'])) json_out(['error' => 'no_challenge'], 400);
        $body = json_body();
        $wa = new \lbuchs\WebAuthn\WebAuthn($config['webauthn_rp_name'], $config['webauthn_rp_id']);
        $challenge = new \lbuchs\WebAuthn\Binary\ByteBuffer($_SESSION['wa_challenge']);
        try {
            $data = $wa->processCreate(
                base64_decode($body['clientDataJSON'] ?? ''),
                base64_decode($body['attestationObject'] ?? ''),
                $challenge,
                'discouraged',
                true, // requireUserPresent
                false // requireUserVerified
            );
        } catch (Throwable $e) {
            json_out(['error' => 'attestation_failed', 'detail' => $e->getMessage()], 400);
        }
        $deviceName = (string)($body['device_name'] ?? 'Dispositivo');
        $ins = db()->prepare("INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, device_name) VALUES (:u, :c, :p, :s, :d)");
        $ins->bindValue(':u', $uid, PDO::PARAM_INT);
        $ins->bindValue(':c', $data->credentialId, PDO::PARAM_LOB);
        $ins->bindValue(':p', $data->credentialPublicKey);
        $ins->bindValue(':s', $data->signatureCounter, PDO::PARAM_INT);
        $ins->bindValue(':d', substr($deviceName, 0, 100));
        $ins->execute();
        unset($_SESSION['wa_challenge']);
        json_out(['ok' => true]);
    }

    // ---- Babies CRUD -----------------------------------------------------
    if (($parts[0] ?? '') === 'babies' && !isset($parts[1]) && $method === 'GET') {
        json_out(list_user_babies($uid));
    }
    if (($parts[0] ?? '') === 'babies' && !isset($parts[1]) && $method === 'POST') {
        $body = json_body();
        $name = trim((string)($body['name'] ?? ''));
        $birth = $body['birthdate'] ?? null;
        $sex = in_array($body['sex'] ?? '', ['girl','boy','other'], true) ? $body['sex'] : 'other';
        $emoji = trim((string)($body['emoji'] ?? '👶'));
        if ($name === '' || strlen($name) > 100) json_out(['error' => 'bad_name'], 400);
        if ($birth && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $birth)) json_out(['error' => 'bad_birthdate'], 400);
        $stmt = db()->prepare("INSERT INTO babies (owner_id, name, birthdate, sex, emoji) VALUES (:o, :n, :b, :s, :e)");
        $stmt->execute([':o' => $uid, ':n' => $name, ':b' => $birth ?: null, ':s' => $sex, ':e' => $emoji ?: '👶']);
        $bid = (int)db()->lastInsertId();
        $_SESSION['baby_id'] = $bid;
        json_out(['ok' => true, 'id' => $bid]);
    }
    if (($parts[0] ?? '') === 'babies' && isset($parts[1]) && ctype_digit($parts[1]) && $method === 'PUT') {
        $bid = (int)$parts[1];
        $acc = baby_access($uid, $bid);
        if (!$acc || !in_array($acc['role'], ['owner','admin','editor'], true)) json_out(['error' => 'forbidden'], 403);
        $body = json_body();
        $fields = []; $params = [':id' => $bid];
        if (isset($body['name'])) {
            $n = trim((string)$body['name']);
            if ($n === '' || strlen($n) > 100) json_out(['error' => 'bad_name'], 400);
            $fields[] = 'name = :n'; $params[':n'] = $n;
        }
        if (array_key_exists('birthdate', $body)) {
            $b = $body['birthdate'];
            if ($b && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $b)) json_out(['error' => 'bad_birthdate'], 400);
            $fields[] = 'birthdate = :b'; $params[':b'] = $b ?: null;
        }
        if (isset($body['sex']) && in_array($body['sex'], ['girl','boy','other'], true)) {
            $fields[] = 'sex = :s'; $params[':s'] = $body['sex'];
        }
        if (isset($body['emoji'])) {
            $fields[] = 'emoji = :e'; $params[':e'] = trim((string)$body['emoji']) ?: '👶';
        }
        if ($fields) {
            $sql = "UPDATE babies SET " . implode(', ', $fields) . " WHERE id = :id";
            db()->prepare($sql)->execute($params);
        }
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === 'babies' && isset($parts[1]) && ctype_digit($parts[1]) && $method === 'DELETE') {
        $bid = (int)$parts[1];
        $acc = baby_access($uid, $bid);
        if (!$acc || $acc['role'] !== 'owner') json_out(['error' => 'forbidden'], 403);
        db()->prepare("DELETE FROM entries WHERE baby_id = ?")->execute([$bid]);
        db()->prepare("DELETE FROM photos WHERE baby_id = ?")->execute([$bid]);
        db()->prepare("DELETE FROM baby_shares WHERE baby_id = ?")->execute([$bid]);
        db()->prepare("DELETE FROM babies WHERE id = ? AND owner_id = ?")->execute([$bid, $uid]);
        if (($_SESSION['baby_id'] ?? null) == $bid) unset($_SESSION['baby_id']);
        json_out(['ok' => true]);
    }

    // ---- Sharing / Invitations -----------------------------------------
    if (($parts[0] ?? '') === 'babies' && isset($parts[1]) && ctype_digit($parts[1]) && ($parts[2] ?? '') === 'invite' && $method === 'POST') {
        $bid = (int)$parts[1];
        $acc = baby_access($uid, $bid);
        if (!$acc || !in_array($acc['role'], ['owner','admin'], true)) json_out(['error' => 'forbidden'], 403);
        $body = json_body();
        $role = in_array($body['role'] ?? '', ['viewer','editor','admin'], true) ? $body['role'] : 'editor';
        $email = isset($body['email']) ? normalize_email((string)$body['email']) : null;
        if ($email !== null && $email !== '' && !is_valid_email($email)) json_out(['error' => 'bad_email'], 400);
        $token = bin2hex(random_bytes(32));
        $stmt = db()->prepare("INSERT INTO invitations (token, baby_id, inviter_id, invitee_email, role, expires_at) VALUES (:t, :b, :i, :em, :r, DATE_ADD(NOW(), INTERVAL 7 DAY))");
        $stmt->execute([':t' => $token, ':b' => $bid, ':i' => $uid, ':em' => $email ?: null, ':r' => $role]);
        json_out(['ok' => true, 'token' => $token, 'expires_days' => 7]);
    }
    if (($parts[0] ?? '') === 'babies' && isset($parts[1]) && ctype_digit($parts[1]) && ($parts[2] ?? '') === 'shares' && $method === 'GET') {
        $bid = (int)$parts[1];
        $acc = baby_access($uid, $bid);
        if (!$acc || !in_array($acc['role'], ['owner','admin'], true)) json_out(['error' => 'forbidden'], 403);
        $stmt = db()->prepare("SELECT s.id, s.role, s.invited_at, s.accepted_at, u.email FROM baby_shares s JOIN users u ON u.id = s.user_id WHERE s.baby_id = ?");
        $stmt->execute([$bid]);
        $shares = $stmt->fetchAll();
        $inv = db()->prepare("SELECT token, invitee_email, role, expires_at, accepted_at FROM invitations WHERE baby_id = ? AND accepted_at IS NULL AND expires_at > NOW()");
        $inv->execute([$bid]);
        $pending = $inv->fetchAll();
        json_out(['shares' => $shares, 'pending' => $pending]);
    }
    if (($parts[0] ?? '') === 'shares' && isset($parts[1]) && ctype_digit($parts[1]) && $method === 'DELETE') {
        $sid = (int)$parts[1];
        // Verificar que el user es owner del baby del share
        $s = db()->prepare("SELECT s.baby_id, b.owner_id FROM baby_shares s JOIN babies b ON b.id = s.baby_id WHERE s.id = ?");
        $s->execute([$sid]);
        $row = $s->fetch();
        if (!$row || (int)$row['owner_id'] !== $uid) json_out(['error' => 'forbidden'], 403);
        db()->prepare("DELETE FROM baby_shares WHERE id = ?")->execute([$sid]);
        json_out(['ok' => true]);
    }
    if (($parts[0] ?? '') === 'invitations' && isset($parts[1]) && ($parts[2] ?? '') === 'accept' && $method === 'POST') {
        $token = $parts[1];
        $stmt = db()->prepare("SELECT * FROM invitations WHERE token = ? AND accepted_at IS NULL AND expires_at > NOW()");
        $stmt->execute([$token]);
        $inv = $stmt->fetch();
        if (!$inv) json_out(['error' => 'invalid_or_expired'], 404);
        // Si tiene invitee_email, verificar que coincide con el user
        if ($inv['invitee_email']) {
            $u = db()->prepare("SELECT email FROM users WHERE id = ?");
            $u->execute([$uid]);
            $urow = $u->fetch();
            if (!$urow || normalize_email($urow['email']) !== normalize_email($inv['invitee_email'])) {
                json_out(['error' => 'email_mismatch', 'expected' => $inv['invitee_email']], 403);
            }
        }
        // No se puede aceptar invitación a bebé propio
        $b = db()->prepare("SELECT owner_id FROM babies WHERE id = ?");
        $b->execute([$inv['baby_id']]);
        $baby = $b->fetch();
        if (!$baby || (int)$baby['owner_id'] === $uid) json_out(['error' => 'own_baby'], 400);
        try {
            $ins = db()->prepare("INSERT INTO baby_shares (baby_id, user_id, role, invited_at, accepted_at) VALUES (:b, :u, :r, :inv, NOW())");
            $ins->execute([':b' => $inv['baby_id'], ':u' => $uid, ':r' => $inv['role'], ':inv' => $inv['created_at']]);
        } catch (PDOException $e) {
            if ((int)$e->errorInfo[1] === 1062) {
                // Ya compartido, solo marca invitación como aceptada
            } else throw $e;
        }
        db()->prepare("UPDATE invitations SET accepted_at = NOW(), accepted_by = ? WHERE token = ?")->execute([$uid, $token]);
        json_out(['ok' => true, 'baby_id' => (int)$inv['baby_id'], 'role' => $inv['role']]);
    }

    // Cambiar bebé activo
    if (($parts[0] ?? '') === 'active_baby' && $method === 'POST') {
        $body = json_body();
        $bid = (int)($body['baby_id'] ?? 0);
        if ($bid <= 0 || !baby_access($uid, $bid)) json_out(['error' => 'no_access_to_baby'], 403);
        $_SESSION['baby_id'] = $bid;
        json_out(['ok' => true, 'baby_id' => $bid]);
    }

    // ---- Datos (JSON blobs por key, scoped a baby) ----------------------
    if (($parts[0] ?? '') === 'data' && $method === 'GET') {
        $bid = resolved_baby_id($uid, get_baby_id_from_request());
        $stmt = db()->prepare("SELECT data_key, data_json FROM entries WHERE baby_id = :b");
        $stmt->execute([':b' => $bid]);
        $out = new stdClass();
        while ($row = $stmt->fetch()) $out->{$row['data_key']} = json_decode($row['data_json'], true);
        json_out($out);
    }
    if (($parts[0] ?? '') === 'data' && $method === 'PUT') {
        $bid = resolved_baby_id($uid, get_baby_id_from_request());
        $acc = baby_access($uid, $bid);
        if ($acc && $acc['role'] === 'viewer') json_out(['error' => 'read_only'], 403);
        $body = json_body();
        $pdo = db();
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("INSERT INTO entries (baby_id, data_key, data_json) VALUES (:b, :k, :v) ON DUPLICATE KEY UPDATE data_json = VALUES(data_json)");
        $count = 0;
        foreach ($body as $key => $value) {
            $stmt->execute([':b' => $bid, ':k' => $key, ':v' => json_encode($value)]);
            $count++;
        }
        $pdo->commit();
        json_out(['ok' => true, 'saved' => $count, 'baby_id' => $bid]);
    }

    // ---- Fotos (scoped a baby) ------------------------------------------
    if (($parts[0] ?? '') === 'photos' && $method === 'GET') {
        $bid = resolved_baby_id($uid, get_baby_id_from_request());
        $stmt = db()->prepare("SELECT id, record_type, record_id, mime, name FROM photos WHERE baby_id = :b");
        $stmt->execute([':b' => $bid]);
        json_out($stmt->fetchAll());
    }
    if (($parts[0] ?? '') === 'photo' && $method === 'POST') {
        $bid = resolved_baby_id($uid, get_baby_id_from_request());
        $acc = baby_access($uid, $bid);
        if ($acc && $acc['role'] === 'viewer') json_out(['error' => 'read_only'], 403);
        $body = json_body();
        $id = (string)($body['id'] ?? bin2hex(random_bytes(16)));
        $mime = (string)($body['mime'] ?? 'image/jpeg');
        $recordType = isset($body['record_type']) ? (string)$body['record_type'] : null;
        $recordId = isset($body['record_id']) ? (int)$body['record_id'] : null;
        $name = isset($body['name']) ? (string)$body['name'] : null;
        $bin = base64_decode((string)($body['data'] ?? ''), true);
        if ($bin === false || $bin === '') json_out(['error' => 'bad_photo'], 400);
        $stmt = db()->prepare("INSERT INTO photos (id, baby_id, record_type, record_id, mime, name, data) VALUES (:id, :b, :rt, :ri, :mime, :name, :data) ON DUPLICATE KEY UPDATE mime = VALUES(mime), name = VALUES(name), record_type = VALUES(record_type), record_id = VALUES(record_id), data = VALUES(data)");
        $stmt->bindValue(':id', $id);
        $stmt->bindValue(':b', $bid, PDO::PARAM_INT);
        $stmt->bindValue(':rt', $recordType);
        $stmt->bindValue(':ri', $recordId, $recordId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':mime', $mime);
        $stmt->bindValue(':name', $name);
        $stmt->bindValue(':data', $bin, PDO::PARAM_LOB);
        $stmt->execute();
        json_out(['ok' => true, 'id' => $id]);
    }
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'GET') {
        // Verificar acceso: la foto debe pertenecer a un baby al que el user tenga acceso
        $stmt = db()->prepare("SELECT mime, data, baby_id FROM photos WHERE id = ?");
        $stmt->execute([$parts[1]]);
        $row = $stmt->fetch();
        if (!$row || !baby_access($uid, (int)$row['baby_id'])) json_out(['error' => 'not_found'], 404);
        header("Content-Type: {$row['mime']}");
        header('Cache-Control: private, max-age=31536000');
        echo $row['data'];
        exit;
    }
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'DELETE') {
        $stmt = db()->prepare("SELECT baby_id FROM photos WHERE id = ?");
        $stmt->execute([$parts[1]]);
        $row = $stmt->fetch();
        if (!$row) json_out(['error' => 'not_found'], 404);
        $acc = baby_access($uid, (int)$row['baby_id']);
        if (!$acc || $acc['role'] === 'viewer') json_out(['error' => 'forbidden'], 403);
        db()->prepare("DELETE FROM photos WHERE id = ?")->execute([$parts[1]]);
        json_out(['ok' => true]);
    }

    json_out(['error' => 'not_found', 'path' => $path], 404);
} catch (Throwable $e) {
    json_out(['error' => 'server_error', 'detail' => $e->getMessage()], 500);
}
