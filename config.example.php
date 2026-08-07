<?php
// Baby Tracker — config.example.php
//
// COPIA este archivo como config.php y colócalo FUERA de public_html:
//   /home/uXXXXXX/private/config.php   (crea la carpeta 'private' si no existe)
//
// NUNCA lo pongas dentro de public_html — router.php lo busca primero en
// private/ y solo cae a public_html/ como último recurso (para dev local).
//
// Permisos recomendados en el server: chmod 600 config.php

return [
    // ---------- Base de datos ----------
    'db_host' => 'localhost',
    'db_name' => 'u696446493_baby_tracker',
    'db_user' => 'u696446493_baby_user',
    'db_pass' => 'PON_AQUI_LA_CONTRASENA_DE_LA_BD',

    // ---------- Claves de crypto ----------
    // 32 bytes en hex (64 chars). Genera con:  openssl rand -hex 32
    // Se usa para cifrar secretos en la BD (TOTP secret, etc.) con AES-256-GCM.
    // Si la cambias, TODOS los secretos cifrados se pierden. Guárdala segura.
    'master_key_hex' => 'RELLENA_CON_openssl_rand_hex_32',

    // Secret para setup inicial. Genera algo random largo (32+ chars).
    // Necesario para acceder a /install.php la primera vez.
    // Después de instalar, cambia a '' para desactivar install.
    'setup_secret' => 'RELLENA_CON_ALGO_RANDOM_LARGO',

    // ---------- WebAuthn / Passkey ----------
    'webauthn_rp_id'   => 'baby.angaes.com',
    'webauthn_rp_name' => 'Baby Tracker',

    // ---------- CORS ----------
    'allowed_origins' => [
        'https://baby.angaes.com',
        'https://garudele.github.io',
    ],

    // ---------- Rate limiting ----------
    'auth_max_attempts'   => 5,          // intentos fallidos antes de bloquear
    'auth_lockout_window' => 900,        // ventana en segundos (15 min)
];
