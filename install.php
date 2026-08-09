<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — install.php  (multi-tenant migration-aware)
// Setup + migraciones. Requiere ?s=<setup_secret> del config.php.
// BORRA este archivo del servidor después de instalar.
// ============================================================================

// Cargar config
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
    echo "config.php no encontrado. Buscado en:\n" . implode("\n", $configPaths);
    exit;
}

// Auth por setup_secret
$s = (string)($_GET['s'] ?? '');
$configuredSecret = (string)($config['setup_secret'] ?? '');
if ($configuredSecret === '') { http_response_code(403); echo "Install desactivado."; exit; }
if (!hash_equals($configuredSecret, $s)) { http_response_code(403); echo "Acceso denegado."; exit; }

// Validar master_key_hex
$hex = (string)($config['master_key_hex'] ?? '');
if (strlen($hex) !== 64 || !ctype_xdigit($hex)) {
    http_response_code(500);
    echo "master_key_hex inválido en config.php (debe ser 64 chars hex).\n";
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

// ---------- Helpers de introspección ----------------------------------------
function col_exists(PDO $pdo, string $table, string $col): bool {
    $s = $pdo->prepare(
        "SELECT COUNT(*) c FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c"
    );
    $s->execute([':t' => $table, ':c' => $col]);
    return (int)$s->fetch()['c'] > 0;
}
function index_exists(PDO $pdo, string $table, string $idx): bool {
    $s = $pdo->prepare(
        "SELECT COUNT(*) c FROM information_schema.statistics
         WHERE table_schema = DATABASE() AND table_name = :t AND index_name = :i"
    );
    $s->execute([':t' => $table, ':i' => $idx]);
    return (int)$s->fetch()['c'] > 0;
}
function table_exists(PDO $pdo, string $table): bool {
    $s = $pdo->prepare(
        "SELECT COUNT(*) c FROM information_schema.tables
         WHERE table_schema = DATABASE() AND table_name = :t"
    );
    $s->execute([':t' => $table]);
    return (int)$s->fetch()['c'] > 0;
}
function run_schema_sql(PDO $pdo): void {
    $sql = file_get_contents(__DIR__ . '/schema.sql');
    if (!$sql) throw new RuntimeException('schema.sql no encontrado');
    foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
        if ($stmt !== '' && stripos($stmt, '--') !== 0) $pdo->exec($stmt);
    }
}
function run_migrations(PDO $pdo): array {
    $applied = [];
    // users: agregar email si no existe
    if (table_exists($pdo, 'users') && !col_exists($pdo, 'users', 'email')) {
        $pdo->exec("ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL AFTER id");
        $applied[] = "users: +email";
    }
    if (table_exists($pdo, 'users') && !col_exists($pdo, 'users', 'email_verified')) {
        $pdo->exec("ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER email");
        $applied[] = "users: +email_verified";
    }
    if (table_exists($pdo, 'users') && !index_exists($pdo, 'users', 'unique_email')) {
        // solo agregar unique si no hay filas con email NULL/duplicado
        $emailless = (int)$pdo->query("SELECT COUNT(*) c FROM users WHERE email IS NULL OR email = ''")->fetch()['c'];
        if ($emailless === 0) {
            $pdo->exec("ALTER TABLE users ADD UNIQUE KEY unique_email (email)");
            $applied[] = "users: +UNIQUE(email)";
        } else {
            $applied[] = "users: UNIQUE(email) skipped ($emailless usuarios sin email)";
        }
    }
    // users.email a NOT NULL una vez que todos tengan email
    if (col_exists($pdo, 'users', 'email')) {
        $nullable = $pdo->query(
            "SELECT is_nullable FROM information_schema.columns
             WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'email'"
        )->fetch();
        if ($nullable && $nullable['is_nullable'] === 'YES') {
            $emailless = (int)$pdo->query("SELECT COUNT(*) c FROM users WHERE email IS NULL OR email = ''")->fetch()['c'];
            if ($emailless === 0) {
                $pdo->exec("ALTER TABLE users MODIFY email VARCHAR(255) NOT NULL");
                $applied[] = "users: email NOT NULL";
            }
        }
    }
    // auth_attempts: agregar email y action si faltan
    if (table_exists($pdo, 'auth_attempts') && !col_exists($pdo, 'auth_attempts', 'email')) {
        $pdo->exec("ALTER TABLE auth_attempts ADD COLUMN email VARCHAR(255) NULL AFTER ip");
        $applied[] = "auth_attempts: +email";
    }
    if (table_exists($pdo, 'auth_attempts') && !col_exists($pdo, 'auth_attempts', 'action')) {
        $pdo->exec("ALTER TABLE auth_attempts ADD COLUMN action VARCHAR(20) NOT NULL DEFAULT 'login' AFTER reason");
        $applied[] = "auth_attempts: +action";
    }
    if (table_exists($pdo, 'auth_attempts') && !index_exists($pdo, 'auth_attempts', 'email_time_idx')) {
        $pdo->exec("ALTER TABLE auth_attempts ADD INDEX email_time_idx (email, attempted_at)");
        $applied[] = "auth_attempts: +INDEX(email,attempted_at)";
    }
    return $applied;
}

$msg = '';
$err = '';
$migrated = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');
    try {
        if ($action === 'setup_schema') {
            run_schema_sql($pdo);
            $migrated = run_migrations($pdo);
            $msg = "Schema OK ✓" . ($migrated ? " · Migraciones: " . implode(', ', $migrated) : "");
        } elseif ($action === 'backfill_email') {
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            $uid = (int)($_POST['uid'] ?? 0);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $err = "Email inválido.";
            elseif ($uid <= 0) $err = "UID inválido.";
            else {
                $up = $pdo->prepare("UPDATE users SET email = :em WHERE id = :id AND (email IS NULL OR email = '')");
                $up->execute([':em' => $email, ':id' => $uid]);
                $msg = "Email actualizado para user #$uid ✓";
                run_migrations($pdo); // intentar completar migraciones ahora que ya hay email
            }
        } elseif ($action === 'create_user') {
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            $pw    = (string)($_POST['password'] ?? '');
            $pw2   = (string)($_POST['password2'] ?? '');
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $err = "Email inválido.";
            elseif (strlen($pw) < 12) $err = "Contraseña ≥ 12 caracteres.";
            elseif ($pw !== $pw2) $err = "Las contraseñas no coinciden.";
            else {
                $hash = password_hash($pw, PASSWORD_ARGON2ID);
                try {
                    $ins = $pdo->prepare("INSERT INTO users (email, password_hash, email_verified) VALUES (:em, :h, 1)");
                    $ins->execute([':em' => $email, ':h' => $hash]);
                    $msg = "Usuario '$email' creado ✓";
                } catch (PDOException $e) {
                    if ((int)$e->errorInfo[1] === 1062) $err = "Ese email ya existe.";
                    else throw $e;
                }
            }
        }
    } catch (Throwable $e) {
        $err = "Error: " . $e->getMessage();
    }
}

// ---------- Estado actual ---------------------------------------------------
$schemaOk = table_exists($pdo, 'users');
$hasEmailCol = $schemaOk && col_exists($pdo, 'users', 'email');
$usersWithoutEmail = [];
$totalUsers = 0;
if ($schemaOk && $hasEmailCol) {
    $totalUsers = (int)$pdo->query("SELECT COUNT(*) c FROM users")->fetch()['c'];
    $stmt = $pdo->query("SELECT id FROM users WHERE email IS NULL OR email = ''");
    $usersWithoutEmail = $stmt->fetchAll(PDO::FETCH_COLUMN);
}
$emailUnique = $schemaOk && index_exists($pdo, 'users', 'unique_email');
$emailNotNull = false;
if ($schemaOk && $hasEmailCol) {
    $ns = $pdo->query("SELECT is_nullable FROM information_schema.columns
                       WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'email'")->fetch();
    $emailNotNull = $ns && $ns['is_nullable'] === 'NO';
}

?><!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install — Baby Tracker</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 560px; margin: 2rem auto; padding: 1rem; line-height: 1.5; }
  h1 { font-size: 1.4rem; margin-bottom: 0; }
  h2 { font-size: 1.1rem; margin-top: 0; }
  .box { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .ok  { background: #e6ffe6; border-color: #7c7; }
  .err { background: #ffe6e6; border-color: #c77; }
  .warn{ background: #fff3cd; border-color: #ecb; }
  label { display: block; margin: 0.5rem 0 0.2rem; font-weight: 600; }
  input { width: 100%; padding: 0.5rem; font-size: 1rem; box-sizing: border-box; }
  button { padding: 0.6rem 1rem; font-size: 1rem; cursor: pointer; }
  .status { font-family: monospace; font-size: 0.9rem; }
  code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
  ul { padding-left: 1.2rem; }
</style>
</head>
<body>
<h1>Baby Tracker — Setup / Migración</h1>
<p style="color:#666;font-size:0.85rem;margin-top:0.3rem;">Multi-tenant</p>

<?php if ($msg): ?><div class="box ok"><?=htmlspecialchars($msg)?></div><?php endif; ?>
<?php if ($err): ?><div class="box err"><?=htmlspecialchars($err)?></div><?php endif; ?>

<div class="box">
  <h2>Estado</h2>
  <div class="status">
    users existe: <?= $schemaOk ? '✓' : '✗' ?><br>
    users.email:  <?= $hasEmailCol ? '✓' : '✗' ?>
    <?= $hasEmailCol && $emailNotNull ? '(NOT NULL ✓)' : ($hasEmailCol ? '(nullable — falta migrar)' : '') ?><br>
    UNIQUE(email): <?= $emailUnique ? '✓' : '✗' ?><br>
    Usuarios totales: <?= $totalUsers ?><br>
    Sin email: <?= count($usersWithoutEmail) ?><?= $usersWithoutEmail ? ' (ids: ' . implode(',', $usersWithoutEmail) . ')' : '' ?>
  </div>
</div>

<div class="box">
  <h2>1. Crear/actualizar schema</h2>
  <p>Corre <code>schema.sql</code> + migraciones idempotentes.</p>
  <form method="POST">
    <input type="hidden" name="action" value="setup_schema">
    <button type="submit">Ejecutar</button>
  </form>
</div>

<?php if ($usersWithoutEmail): ?>
<div class="box warn">
  <h2>2. Backfill de email (usuarios legacy)</h2>
  <p>Hay <?= count($usersWithoutEmail) ?> usuario(s) sin email. Asígnales uno para completar la migración.</p>
  <?php foreach ($usersWithoutEmail as $uid): ?>
    <form method="POST" style="margin-bottom:0.5rem;">
      <input type="hidden" name="action" value="backfill_email">
      <input type="hidden" name="uid" value="<?=htmlspecialchars((string)$uid)?>">
      <label>Email para user #<?=htmlspecialchars((string)$uid)?></label>
      <input type="email" name="email" required>
      <button type="submit" style="margin-top:0.3rem;">Guardar email</button>
    </form>
  <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="box">
  <h2><?= $usersWithoutEmail ? '3' : '2' ?>. Crear nuevo usuario (opcional)</h2>
  <p>Usa esto solo si quieres crear otro usuario desde install. Normalmente el signup lo hacen los usuarios desde la app.</p>
  <form method="POST" autocomplete="off">
    <input type="hidden" name="action" value="create_user">
    <label>Email</label>
    <input type="email" name="email" required>
    <label>Contraseña (≥12 chars)</label>
    <input type="password" name="password" required minlength="12">
    <label>Confirmar</label>
    <input type="password" name="password2" required minlength="12">
    <button type="submit" style="margin-top:0.5rem;">Crear</button>
  </form>
</div>

<?php if ($schemaOk && $emailUnique && $emailNotNull): ?>
<div class="box warn">
  <strong>¡Setup completo!</strong>
  <p><strong>Antes de exponer la app:</strong></p>
  <ul>
    <li>Borra <code>install.php</code> del servidor</li>
    <li>Quita el bloque <code>_diag</code> de <code>router.php</code></li>
    <li>En <code>config.php</code> cambia <code>setup_secret</code> a <code>''</code> (o solo bórralo del server temporalmente)</li>
  </ul>
</div>
<?php endif; ?>

</body>
</html>
