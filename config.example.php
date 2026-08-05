<?php
// Copia este archivo como config.php y llena los valores reales.
// NUNCA subas config.php a GitHub — ya está en .gitignore.
return [
    'db_host'     => 'localhost',
    'db_name'     => 'u696446493_baby_tracker',
    'db_user'     => 'u696446493_baby_user',
    'db_pass'     => 'PON_AQUI_LA_CONTRASENA_DE_LA_BD',

    // Contraseña con la que TÚ vas a entrar al app (invéntala distinta a la de la BD)
    'app_password' => 'PON_AQUI_UNA_CONTRASENA_PARA_ENTRAR_AL_APP',

    // De dónde puede llamar el frontend. Deja el subdominio y opcionalmente el de GH Pages.
    'allowed_origins' => [
        'https://baby.angaes.com',
        'https://garudele.github.io',
    ],
];
