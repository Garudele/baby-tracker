<?php
declare(strict_types=1);

// ============================================================================
// Baby Tracker — install.php  (multi-tenant + babies migration)
// Requiere ?s=<setup_secret> del config.php.
// Pon setup_secret='' cuando termines para desactivar.
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
if (!$config) { http_response_code(500); echo "config.php no encontrado."; exit; }

$s = (string)($_GET['s'] ?? '');
$configuredSecret = (string)($config['setup_secret'] ?? '');
if ($configuredSecret === '') { http_response_code(403); echo "Install desactivado (setup_secret vacío)."; exit; }
if (!hash_equals($configuredSecret, $s)) { http_response_code(403); echo "Acceso denegado."; exit; }

try {
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4",
        $config['db_user'], $config['db_pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (Throwable $e) { http_response_code(500); echo "DB: " . $e->getMessage(); exit; }

function col_exists(PDO $pdo, string $t, string $c): bool {
    $s = $pdo->prepare("SELECT COUNT(*) c FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=:t AND column_name=:c");
    $s->execute([':t'=>$t, ':c'=>$c]);
    return (int)$s->fetch()['c'] > 0;
}
function index_exists(PDO $pdo, string $t, string $i): bool {
    $s = $pdo->prepare("SELECT COUNT(*) c FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=:t AND index_name=:i");
    $s->execute([':t'=>$t, ':i'=>$i]);
    return (int)$s->fetch()['c'] > 0;
}
function table_exists(PDO $pdo, string $t): bool {
    $s = $pdo->prepare("SELECT COUNT(*) c FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=:t");
    $s->execute([':t'=>$t]);
    return (int)$s->fetch()['c'] > 0;
}
function run_schema_sql(PDO $pdo): void {
    $sql = file_get_contents(__DIR__ . '/schema.sql');
    if (!$sql) throw new RuntimeException('schema.sql no encontrado');
    $lines = array_filter(explode("\n", $sql), fn($l) => !preg_match('/^\s*(--|$)/', $l));
    $clean = implode("\n", $lines);
    foreach (array_filter(array_map('trim', explode(';', $clean))) as $stmt) {
        if ($stmt !== '') $pdo->exec($stmt);
    }
}

$msg = ''; $err = ''; $migrated = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');
    try {
        if ($action === 'setup_schema') {
            run_schema_sql($pdo);

            // ---------- Migraciones users ------------------------------------
            if (table_exists($pdo, 'users') && !col_exists($pdo, 'users', 'email')) {
                $pdo->exec("ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL AFTER id");
                $migrated[] = "users:+email";
            }
            if (table_exists($pdo, 'users') && !col_exists($pdo, 'users', 'email_verified')) {
                $pdo->exec("ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER email");
                $migrated[] = "users:+email_verified";
            }
            $emailless = (int)$pdo->query("SELECT COUNT(*) c FROM users WHERE email IS NULL OR email = ''")->fetch()['c'];
            if ($emailless === 0 && !index_exists($pdo, 'users', 'unique_email')) {
                $pdo->exec("ALTER TABLE users ADD UNIQUE KEY unique_email (email)");
                $migrated[] = "users:+UNIQUE(email)";
            }

            // ---------- Migraciones auth_attempts ----------------------------
            if (table_exists($pdo, 'auth_attempts') && !col_exists($pdo, 'auth_attempts', 'email')) {
                $pdo->exec("ALTER TABLE auth_attempts ADD COLUMN email VARCHAR(255) NULL AFTER ip");
                $migrated[] = "auth_attempts:+email";
            }
            if (table_exists($pdo, 'auth_attempts') && !col_exists($pdo, 'auth_attempts', 'action')) {
                $pdo->exec("ALTER TABLE auth_attempts ADD COLUMN action VARCHAR(20) NOT NULL DEFAULT 'login' AFTER reason");
                $migrated[] = "auth_attempts:+action";
            }

            // ---------- Migraciones entries/photos: user_id → baby_id --------
            // Estrategia: crear default baby por usuario si tiene data en entries/photos con user_id
            if (table_exists($pdo, 'entries') && col_exists($pdo, 'entries', 'user_id') && !col_exists($pdo, 'entries', 'baby_id')) {
                // 1) Añadir columna baby_id
                $pdo->exec("ALTER TABLE entries ADD COLUMN baby_id INT UNSIGNED NULL AFTER user_id");
                // 2) Crear un baby por cada user_id distinto en entries
                $stmt = $pdo->query("SELECT DISTINCT user_id FROM entries WHERE user_id IS NOT NULL");
                while ($row = $stmt->fetch()) {
                    $uid = (int)$row['user_id'];
                    // Verificar user existe
                    $chk = $pdo->prepare("SELECT id FROM users WHERE id = ?");
                    $chk->execute([$uid]);
                    if (!$chk->fetch()) continue;
                    // Crear baby default si no tiene
                    $b = $pdo->prepare("SELECT id FROM babies WHERE owner_id = ? ORDER BY id LIMIT 1");
                    $b->execute([$uid]);
                    $baby = $b->fetch();
                    if (!$baby) {
                        $ins = $pdo->prepare("INSERT INTO babies (owner_id, name, emoji) VALUES (?, 'Mi bebé', '👶')");
                        $ins->execute([$uid]);
                        $babyId = (int)$pdo->lastInsertId();
                    } else {
                        $babyId = (int)$baby['id'];
                    }
                    // Backfill
                    $up = $pdo->prepare("UPDATE entries SET baby_id = ? WHERE user_id = ? AND baby_id IS NULL");
                    $up->execute([$babyId, $uid]);
                    $migrated[] = "entries: user $uid → baby $babyId";
                }
                // 3) Dropear PK vieja, hacer baby_id NOT NULL, nueva PK
                $pdo->exec("ALTER TABLE entries DROP PRIMARY KEY, MODIFY baby_id INT UNSIGNED NOT NULL, ADD PRIMARY KEY (baby_id, data_key)");
                $pdo->exec("ALTER TABLE entries DROP COLUMN user_id");
                $migrated[] = "entries: schema migrado a baby_id";
            }

            if (table_exists($pdo, 'photos') && col_exists($pdo, 'photos', 'user_id') && !col_exists($pdo, 'photos', 'baby_id')) {
                $pdo->exec("ALTER TABLE photos ADD COLUMN baby_id INT UNSIGNED NULL AFTER user_id");
                $stmt = $pdo->query("SELECT DISTINCT user_id FROM photos WHERE user_id IS NOT NULL");
                while ($row = $stmt->fetch()) {
                    $uid = (int)$row['user_id'];
                    $b = $pdo->prepare("SELECT id FROM babies WHERE owner_id = ? ORDER BY id LIMIT 1");
                    $b->execute([$uid]);
                    $baby = $b->fetch();
                    if (!$baby) continue;
                    $babyId = (int)$baby['id'];
                    $up = $pdo->prepare("UPDATE photos SET baby_id = ? WHERE user_id = ? AND baby_id IS NULL");
                    $up->execute([$babyId, $uid]);
                }
                $pdo->exec("ALTER TABLE photos MODIFY baby_id INT UNSIGNED NOT NULL");
                $pdo->exec("ALTER TABLE photos DROP COLUMN user_id");
                $migrated[] = "photos: schema migrado a baby_id";
            }

            $msg = "Schema OK ✓" . ($migrated ? " · " . implode(', ', $migrated) : " (sin cambios)");
        } elseif ($action === 'reset_data') {
            // Peligro: borrar entries/photos y recrearlos con nuevo schema (baby_id)
            $pdo->exec("DROP TABLE IF EXISTS entries");
            $pdo->exec("DROP TABLE IF EXISTS photos");
            run_schema_sql($pdo);
            $msg = "Tablas entries y photos recreadas con nuevo schema ✓";
        } elseif ($action === 'gen_vapid') {
            require_once __DIR__ . '/lib/WebPush.php';
            $keys = \BabyTracker\WebPush::generateVapidKeys();
            $msg = "VAPID keys generadas ✓ — COPIA a private/config.php:\n\n"
                . "'vapid_public_key'  => '" . $keys['public'] . "',\n"
                . "'vapid_private_key' => '" . $keys['private'] . "',";
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
                    if ((int)$e->errorInfo[1] === 1062) $err = "Email ya existe.";
                    else throw $e;
                }
            }
        }
    } catch (Throwable $e) {
        $err = "Error: " . $e->getMessage();
    }
}

$totalUsers = 0; $totalBabies = 0; $entriesHasBabyId = false; $entriesHasUserId = false;
try {
    if (table_exists($pdo, 'users')) $totalUsers = (int)$pdo->query("SELECT COUNT(*) c FROM users")->fetch()['c'];
    if (table_exists($pdo, 'babies')) $totalBabies = (int)$pdo->query("SELECT COUNT(*) c FROM babies")->fetch()['c'];
    if (table_exists($pdo, 'entries')) {
        $entriesHasBabyId = col_exists($pdo, 'entries', 'baby_id');
        $entriesHasUserId = col_exists($pdo, 'entries', 'user_id');
    }
} catch (Throwable $e) {}

?><!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install — Baby Tracker</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:560px;margin:2rem auto;padding:1rem;line-height:1.5}
  h1{font-size:1.4rem;margin-bottom:0}h2{font-size:1.05rem;margin-top:0}
  .box{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
  .ok{background:#e6ffe6;border-color:#7c7}.err{background:#ffe6e6;border-color:#c77}
  .warn{background:#fff3cd;border-color:#ecb}
  label{display:block;margin:.5rem 0 .2rem;font-weight:600}
  input{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}
  button{padding:.6rem 1rem;font-size:1rem;cursor:pointer;border:1px solid #ccc;border-radius:6px;background:#f0f0f0}
  .danger{background:#ffe6e6;border-color:#c77;color:#a00}
  .status{font-family:monospace;font-size:.9rem}
</style>
</head>
<body>
<h1>Baby Tracker — Setup / Migración</h1>
<p style="color:#666;font-size:.85rem;margin-top:.3rem">Multi-tenant + Bebés</p>

<?php if($msg):?><div class="box ok" style="white-space:pre-wrap;font-family:monospace;font-size:0.85rem"><?=htmlspecialchars($msg)?></div><?php endif;?>
<?php if($err):?><div class="box err"><?=htmlspecialchars($err)?></div><?php endif;?>

<div class="box">
  <h2>Estado</h2>
  <div class="status">
    Usuarios: <?= $totalUsers ?><br>
    Bebés: <?= $totalBabies ?><br>
    entries.baby_id: <?= $entriesHasBabyId ? '✓' : '✗' ?><br>
    entries.user_id (legacy): <?= $entriesHasUserId ? 'aún existe' : 'removida ✓' ?>
  </div>
</div>

<div class="box">
  <h2>1. Ejecutar schema + migraciones</h2>
  <p>Idempotente. Corre schema.sql y aplica migraciones pendientes.</p>
  <form method="POST"><input type="hidden" name="action" value="setup_schema"><button type="submit">Ejecutar</button></form>
</div>

<div class="box warn">
  <h2>2. Reset de entries/photos (destructivo)</h2>
  <p>Solo si la migración normal falla. <strong>Borra todas las entries y photos del server</strong>. Los datos locales (localStorage/IndexedDB) del navegador NO se afectan.</p>
  <form method="POST" onsubmit="return confirm('¿Seguro? Se borrarán las entries y photos del servidor.')">
    <input type="hidden" name="action" value="reset_data">
    <button type="submit" class="danger">Reset entries + photos</button>
  </form>
</div>

<div class="box">
  <h2>3. Generar VAPID keys (para Push notifications)</h2>
  <p>Genera un par de llaves ECDSA P-256 para autenticar el envío de push notifications. Copia el resultado a <code>private/config.php</code>.</p>
  <form method="POST">
    <input type="hidden" name="action" value="gen_vapid">
    <button type="submit">Generar VAPID keys</button>
  </form>
</div>

<div class="box">
  <h2>4. Crear usuario manual (opcional)</h2>
  <form method="POST" autocomplete="off">
    <input type="hidden" name="action" value="create_user">
    <label>Email</label><input type="email" name="email" required>
    <label>Contraseña (≥12 chars)</label><input type="password" name="password" required minlength="12">
    <label>Confirmar</label><input type="password" name="password2" required minlength="12">
    <button type="submit" style="margin-top:.5rem">Crear</button>
  </form>
</div>

<div class="box warn">
  <strong>Cuando termines:</strong> pon <code>setup_secret</code> a <code>''</code> en <code>/home/uXXX/private/config.php</code>.
</div>
</body>
</html>
