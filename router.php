<?php
declare(strict_types=1);

// Diag temprano — no requiere config.php. BORRAR después.
if (($_GET['t'] ?? '') === 'baby-diag-2026'
    && strpos($_SERVER['REQUEST_URI'] ?? '', '_diag') !== false) {
    header('Content-Type: text/plain; charset=utf-8');
    $algos = password_algos();
    $lines = [
        "PHP Version: " . PHP_VERSION,
        "SAPI: " . PHP_SAPI,
        "Algoritmos password: " . implode(', ', $algos),
        "Argon2id: " . (in_array(PASSWORD_ARGON2ID, $algos, true) ? "SI" : "NO"),
        "Argon2i:  " . (in_array(PASSWORD_ARGON2I,  $algos, true) ? "SI" : "NO"),
        "sodium ext: " . (extension_loaded('sodium') ? "SI" : "NO"),
        "openssl ext: " . (extension_loaded('openssl') ? "SI" : "NO"),
        "vendor/autoload: " . (file_exists(__DIR__ . '/vendor/autoload.php') ? "SI" : "NO"),
        "config.php existe: " . (file_exists(__DIR__ . '/config.php') ? "SI" : "NO"),
        "session.cookie_samesite: " . ini_get('session.cookie_samesite'),
        "extensiones: pdo_mysql=" . (extension_loaded('pdo_mysql')?'SI':'NO')
            . " mbstring=" . (extension_loaded('mbstring')?'SI':'NO')
            . " gd=" . (extension_loaded('gd')?'SI':'NO')
            . " curl=" . (extension_loaded('curl')?'SI':'NO'),
    ];
    echo implode("\n", $lines);
    exit;
}

$config = require __DIR__ . '/config.php';

// ---------- CORS ----------
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $config['allowed_origins'], true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Vary: Origin");
}
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ---------- Session ----------
session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'None',
]);
session_name('baby_sess');
session_start();

// ---------- Helpers ----------
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
    if (empty($_SESSION['auth'])) json_out(['error' => 'unauthorized'], 401);
}

// ---------- Router ----------
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '';
$path = preg_replace('#^.*?/api/?#', '', $path);
$path = trim($path, '/');
$parts = $path === '' ? [] : explode('/', $path);
$method = $_SERVER['REQUEST_METHOD'];

try {
    // Estado de sesión (sin auth)
    if (($parts[0] ?? '') === 'me' && $method === 'GET') {
        json_out(['auth' => !empty($_SESSION['auth'])]);
    }

    // Diagnóstico temporal (sin auth, gated por token). BORRAR después.
    if (($parts[0] ?? '') === '_diag' && ($_GET['t'] ?? '') === 'baby-diag-2026') {
        header('Content-Type: text/plain; charset=utf-8');
        $algos = password_algos();
        $lines = [
            "PHP Version: " . PHP_VERSION,
            "SAPI: " . PHP_SAPI,
            "Algoritmos password: " . implode(', ', $algos),
            "Argon2id: " . (in_array(PASSWORD_ARGON2ID, $algos, true) ? "SI" : "NO"),
            "Argon2i:  " . (in_array(PASSWORD_ARGON2I,  $algos, true) ? "SI" : "NO"),
            "sodium ext: " . (extension_loaded('sodium') ? "SI" : "NO"),
            "openssl ext: " . (extension_loaded('openssl') ? "SI" : "NO"),
            "vendor/autoload: " . (file_exists(__DIR__ . '/vendor/autoload.php') ? "SI" : "NO"),
            "composer en PATH: " . (trim((string)shell_exec('command -v composer 2>&1')) ?: "NO"),
            "session.cookie_samesite: " . ini_get('session.cookie_samesite'),
            "extensiones: pdo_mysql=" . (extension_loaded('pdo_mysql')?'SI':'NO')
                . " mbstring=" . (extension_loaded('mbstring')?'SI':'NO')
                . " gd=" . (extension_loaded('gd')?'SI':'NO')
                . " curl=" . (extension_loaded('curl')?'SI':'NO'),
        ];
        echo implode("\n", $lines);
        exit;
    }

    // Login
    if (($parts[0] ?? '') === 'login' && $method === 'POST') {
        $body = json_body();
        $pw = (string)($body['password'] ?? '');
        if (hash_equals((string)$config['app_password'], $pw)) {
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            json_out(['ok' => true]);
        }
        // Pequeña espera para desalentar fuerza bruta
        usleep(500000);
        json_out(['error' => 'bad_password'], 401);
    }

    // Logout
    if (($parts[0] ?? '') === 'logout' && $method === 'POST') {
        $_SESSION = [];
        session_destroy();
        json_out(['ok' => true]);
    }

    // A partir de aquí, requiere sesión
    require_auth();

    // GET /api/data → { info: {...}, growth: [...], vaccines: [...], ... }
    if (($parts[0] ?? '') === 'data' && $method === 'GET') {
        $stmt = db()->query("SELECT data_key, data_json FROM entries WHERE user_id = 1");
        $out = new stdClass();
        while ($row = $stmt->fetch()) {
            $out->{$row['data_key']} = json_decode($row['data_json'], true);
        }
        json_out($out);
    }

    // PUT /api/data → recibe { key: value, ... } y hace upsert de todo
    if (($parts[0] ?? '') === 'data' && $method === 'PUT') {
        $body = json_body();
        $pdo = db();
        $pdo->beginTransaction();
        $stmt = $pdo->prepare(
            "INSERT INTO entries (user_id, data_key, data_json) VALUES (1, :k, :v)
             ON DUPLICATE KEY UPDATE data_json = VALUES(data_json)"
        );
        $count = 0;
        foreach ($body as $key => $value) {
            $stmt->execute([':k' => $key, ':v' => json_encode($value)]);
            $count++;
        }
        $pdo->commit();
        json_out(['ok' => true, 'saved' => $count]);
    }

    // GET /api/photos → lista {id, record_type, record_id, mime, name} (sin blobs)
    if (($parts[0] ?? '') === 'photos' && $method === 'GET') {
        $stmt = db()->query("SELECT id, record_type, record_id, mime, name FROM photos WHERE user_id = 1");
        json_out($stmt->fetchAll());
    }

    // POST /api/photo  { id?, record_type?, record_id?, mime, name?, data (base64) }
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
             VALUES (:id, 1, :rt, :ri, :mime, :name, :data)
             ON DUPLICATE KEY UPDATE mime = VALUES(mime), name = VALUES(name),
                                     record_type = VALUES(record_type), record_id = VALUES(record_id),
                                     data = VALUES(data)"
        );
        $stmt->bindValue(':id', $id);
        $stmt->bindValue(':rt', $recordType);
        $stmt->bindValue(':ri', $recordId, $recordId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':mime', $mime);
        $stmt->bindValue(':name', $name);
        $stmt->bindValue(':data', $bin, PDO::PARAM_LOB);
        $stmt->execute();
        json_out(['ok' => true, 'id' => $id]);
    }

    // GET /api/photo/{id} → sirve el binario
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'GET') {
        $stmt = db()->prepare("SELECT mime, data FROM photos WHERE id = ? AND user_id = 1");
        $stmt->execute([$parts[1]]);
        $row = $stmt->fetch();
        if (!$row) json_out(['error' => 'not_found'], 404);
        header("Content-Type: {$row['mime']}");
        header('Cache-Control: private, max-age=31536000');
        echo $row['data'];
        exit;
    }

    // DELETE /api/photo/{id}
    if (($parts[0] ?? '') === 'photo' && isset($parts[1]) && $method === 'DELETE') {
        $stmt = db()->prepare("DELETE FROM photos WHERE id = ? AND user_id = 1");
        $stmt->execute([$parts[1]]);
        json_out(['ok' => true]);
    }

    json_out(['error' => 'not_found', 'path' => $path], 404);
} catch (Throwable $e) {
    json_out(['error' => 'server_error', 'detail' => $e->getMessage()], 500);
}
