<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — install.php
// Setup inicial: crea tablas y hashea la contraseña maestra con Argon2id.
// Requiere ?s=<setup_secret> del config.php para acceder.
// BORRA este archivo del servidor después de instalar.
// ============================================================================

// Cargar config (misma lógica que router.php)
$configPaths = [
    dirname(dirname(__DIR__)) . '/private/config.php',
    dirname(__DIR__) . '/private/config.php',
    __DIR__ . '/config.php',
];
$config = null;
foreach ($configPaths as $p) {
    if (file_exists($p)) { $config = require $p; break; }
}
if (!$config) {
    http_response_code(500);
    echo "config.php no encontrado. Buscado en:\n" . implode("\n", $configPaths);
    exit;
}

// Auth por setup_secret
$s = (string)($_GET['s'] ?? '');
$configuredSecret = (string)($config['setup_secret'] ?? '');
if ($configuredSecret === '') {
    http_response_code(403);
    echo "Install desactivado (setup_secret vacío en config.php).";
    exit;
}
if (!hash_equals($configuredSecret, $s)) {
    http_response_code(403);
    echo "Acceso denegado.";
    exit;
}

// Validar master_key_hex
$hex = (string)($config['master_key_hex'] ?? '');
if (strlen($hex) !== 64 || !ctype_xdigit($hex)) {
    http_response_code(500);
    echo "master_key_hex inválido en config.php (debe ser 64 chars hex).\n";
    echo "Genera con: openssl rand -hex 32\n";
    exit;
}

// DB
try {
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4",
        $config['db_user'],
        $config['db_pass'],
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (Throwable $e) {
    http_response_code(500);
    echo "No pude conectar a la BD: " . $e->getMessage();
    exit;
}

$msg = '';
$err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'create_schema') {
        try {
            $sql = file_get_contents(__DIR__ . '/schema.sql');
            if (!$sql) throw new RuntimeException('schema.sql no encontrado en ' . __DIR__);
            foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
                if ($stmt !== '' && stripos($stmt, '--') !== 0) {
                    $pdo->exec($stmt);
                }
            }
            $msg = "Tablas creadas ✓";
        } catch (Throwable $e) {
            $err = "Error creando tablas: " . $e->getMessage();
        }
    } elseif ($action === 'set_password') {
        $pw = (string)($_POST['password'] ?? '');
        $pw2 = (string)($_POST['password2'] ?? '');
        if (strlen($pw) < 12) {
            $err = "La contraseña debe tener al menos 12 caracteres.";
        } elseif ($pw !== $pw2) {
            $err = "Las contraseñas no coinciden.";
        } else {
            try {
                $hash = password_hash($pw, PASSWORD_ARGON2ID);
                $exists = (int)$pdo->query("SELECT COUNT(*) c FROM users WHERE id = 1")->fetch()['c'];
                if ($exists) {
                    $up = $pdo->prepare("UPDATE users SET password_hash = :h WHERE id = 1");
                    $up->execute([':h' => $hash]);
                    $msg = "Contraseña actualizada ✓ (usuario ya existía)";
                } else {
                    $ins = $pdo->prepare("INSERT INTO users (id, password_hash) VALUES (1, :h)");
                    $ins->execute([':h' => $hash]);
                    $msg = "Usuario creado ✓ con Argon2id";
                }
            } catch (Throwable $e) {
                $err = "Error guardando password: " . $e->getMessage();
            }
        }
    }
}

// Estado actual
$schemaOk = false;
$userOk = false;
try {
    $pdo->query("SELECT 1 FROM users LIMIT 1");
    $schemaOk = true;
    $userOk = (int)$pdo->query("SELECT COUNT(*) c FROM users WHERE id = 1")->fetch()['c'] > 0;
} catch (Throwable $e) {}

?><!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install — Baby Tracker</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 2rem auto; padding: 1rem; }
  h1 { font-size: 1.4rem; }
  .box { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .ok  { background: #e6ffe6; border-color: #7c7; }
  .err { background: #ffe6e6; border-color: #c77; }
  .warn{ background: #fff3cd; border-color: #ecb; }
  label { display: block; margin: 0.5rem 0 0.2rem; font-weight: 600; }
  input[type=password] { width: 100%; padding: 0.5rem; font-size: 1rem; box-sizing: border-box; }
  button { padding: 0.6rem 1rem; font-size: 1rem; cursor: pointer; }
  .status { font-family: monospace; font-size: 0.9rem; }
  code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
</style>
</head>
<body>
<h1>Baby Tracker — Setup</h1>

<?php if ($msg): ?>
  <div class="box ok"><?=htmlspecialchars($msg)?></div>
<?php endif; ?>
<?php if ($err): ?>
  <div class="box err"><?=htmlspecialchars($err)?></div>
<?php endif; ?>

<div class="box">
  <div class="status">
    Schema: <?= $schemaOk ? '✓ creado' : '✗ falta' ?><br>
    Usuario: <?= $userOk ? '✓ existe' : '✗ falta' ?>
  </div>
</div>

<div class="box">
  <h2 style="margin-top:0;font-size:1.1rem;">Paso 1 — Crear tablas</h2>
  <form method="POST">
    <input type="hidden" name="action" value="create_schema">
    <button type="submit"<?= $schemaOk ? ' disabled' : '' ?>>
      <?= $schemaOk ? 'Ya creadas' : 'Crear/actualizar tablas' ?>
    </button>
  </form>
</div>

<div class="box">
  <h2 style="margin-top:0;font-size:1.1rem;">Paso 2 — Contraseña maestra</h2>
  <form method="POST" autocomplete="off">
    <input type="hidden" name="action" value="set_password">
    <label>Contraseña (mín. 12 caracteres)</label>
    <input type="password" name="password" required minlength="12">
    <label>Confirmar</label>
    <input type="password" name="password2" required minlength="12">
    <div style="margin-top:0.5rem;">
      <button type="submit"<?= $schemaOk ? '' : ' disabled' ?>>
        <?= $userOk ? 'Cambiar contraseña' : 'Crear usuario' ?>
      </button>
    </div>
  </form>
</div>

<?php if ($schemaOk && $userOk): ?>
<div class="box warn">
  <strong>¡Listo!</strong> Ya puedes entrar al app. <br><br>
  <strong>Ahora borra:</strong>
  <ul>
    <li><code>install.php</code> del servidor</li>
    <li>La ruta <code>_diag</code> del <code>router.php</code></li>
    <li>Cambia <code>setup_secret</code> a <code>''</code> en <code>config.php</code></li>
  </ul>
</div>
<?php endif; ?>

</body>
</html>
