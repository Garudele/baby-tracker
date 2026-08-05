<?php
// Diagnóstico temporal — BORRAR después de leer.
// Acceso protegido con token para evitar exposición pública.
$token = $_GET['t'] ?? '';
if ($token !== 'baby-diag-2026') {
    http_response_code(404);
    exit;
}

header('Content-Type: text/plain; charset=utf-8');

echo "=== PHP ===\n";
echo "Version: " . PHP_VERSION . "\n";
echo "SAPI:    " . PHP_SAPI . "\n\n";

echo "=== Hashing ===\n";
$algos = password_algos();
echo "Algoritmos disponibles: " . implode(', ', $algos) . "\n";
echo "Argon2id soportado:     " . (in_array(PASSWORD_ARGON2ID, $algos, true) ? "SI" : "NO") . "\n";
echo "Argon2i  soportado:     " . (in_array(PASSWORD_ARGON2I,  $algos, true) ? "SI" : "NO") . "\n";
echo "sodium ext:             " . (extension_loaded('sodium') ? "SI" : "NO") . "\n\n";

echo "=== Crypto ===\n";
echo "openssl ext:            " . (extension_loaded('openssl') ? "SI" : "NO") . "\n";
echo "random_bytes():         " . (function_exists('random_bytes') ? "SI" : "NO") . "\n\n";

echo "=== Composer ===\n";
$paths = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
];
$found = false;
foreach ($paths as $p) {
    if (file_exists($p)) { echo "vendor/autoload.php en: $p\n"; $found = true; }
}
if (!$found) echo "vendor/autoload.php: NO encontrado\n";
$composerBin = shell_exec('command -v composer 2>&1');
echo "composer en PATH:       " . (trim((string)$composerBin) ?: "NO") . "\n\n";

echo "=== Sesion / cookies ===\n";
echo "session.cookie_samesite: " . ini_get('session.cookie_samesite') . "\n";
echo "session.cookie_secure:   " . ini_get('session.cookie_secure') . "\n\n";

echo "=== Extensiones utiles ===\n";
foreach (['pdo_mysql','mbstring','json','gd','curl','fileinfo','zip'] as $ext) {
    echo str_pad($ext, 15) . (extension_loaded($ext) ? "SI" : "NO") . "\n";
}
