<?php
declare(strict_types=1);

// ============================================================================
// WebPush.php — Envío de push notifications vía Web Push Protocol (RFC 8291)
// - VAPID authentication (RFC 8292) con JWT ES256
// - Payload encryption aes128gcm (RFC 8188)
// Sin dependencias externas más allá de PHP >= 7.3 + ext-openssl
// ============================================================================

namespace BabyTracker;

class WebPush {
    private string $vapidPubB64;      // base64url uncompressed EC point (65 bytes)
    private string $vapidPrivB64;     // base64url raw private key (32 bytes)
    private string $subject;          // mailto:...  o URL

    public function __construct(string $publicKeyB64, string $privateKeyB64, string $subject) {
        $this->vapidPubB64  = $publicKeyB64;
        $this->vapidPrivB64 = $privateKeyB64;
        $this->subject      = $subject;
    }

    /**
     * Envía un mensaje a UNA suscripción.
     * $subscription = ['endpoint' => ..., 'p256dh' => base64url, 'auth' => base64url]
     * $payload = string (JSON o texto). Max ~4KB.
     * Devuelve [ok:bool, code:int, error:?string]
     */
    public function send(array $subscription, string $payload, int $ttl = 3600): array {
        try {
            $aud = $this->getAudience($subscription['endpoint']);
            $jwt = $this->makeVapidJwt($aud);
            $body = $this->encrypt(
                $payload,
                self::b64urlDec($subscription['p256dh']),
                self::b64urlDec($subscription['auth'])
            );
        } catch (\Throwable $e) {
            return ['ok' => false, 'code' => 0, 'error' => 'crypto: ' . $e->getMessage()];
        }

        $ch = curl_init($subscription['endpoint']);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => [
                'Authorization: vapid t=' . $jwt . ', k=' . $this->vapidPubB64,
                'Content-Encoding: aes128gcm',
                'Content-Type: application/octet-stream',
                'Content-Length: ' . strlen($body),
                'TTL: ' . $ttl,
            ],
            CURLOPT_POSTFIELDS => $body,
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        return [
            'ok' => $code >= 200 && $code < 300,
            'code' => $code,
            'error' => $err ?: ($code >= 400 ? substr((string)$resp, 0, 300) : null),
        ];
    }

    // ---------- VAPID JWT ---------------------------------------------------
    private function makeVapidJwt(string $aud): string {
        $header  = ['typ' => 'JWT', 'alg' => 'ES256'];
        $payload = ['aud' => $aud, 'exp' => time() + 12 * 3600, 'sub' => $this->subject];
        $hb = self::b64url(json_encode($header, JSON_UNESCAPED_SLASHES));
        $pb = self::b64url(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signingInput = $hb . '.' . $pb;

        $privPem = self::ecPrivateKeyPem(self::b64urlDec($this->vapidPrivB64), self::b64urlDec($this->vapidPubB64));
        $key = openssl_pkey_get_private($privPem);
        if (!$key) throw new \RuntimeException('bad vapid private key: ' . openssl_error_string());
        if (!openssl_sign($signingInput, $sig, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('sign failed');
        }
        $rawSig = self::derToRawEcSig($sig);
        return $signingInput . '.' . self::b64url($rawSig);
    }

    // ---------- Payload encryption (aes128gcm) -----------------------------
    private function encrypt(string $plain, string $p256dh, string $auth): string {
        // 1) Ephemeral EC key
        $ephKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if (!$ephKey) throw new \RuntimeException('gen ephemeral: ' . openssl_error_string());
        $ephDetails = openssl_pkey_get_details($ephKey);
        $ephX = str_pad($ephDetails['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $ephY = str_pad($ephDetails['ec']['y'], 32, "\x00", STR_PAD_LEFT);
        $ephPub = "\x04" . $ephX . $ephY;  // 65 bytes uncompressed

        // 2) ECDH shared secret
        $subPubPem = self::ecPublicKeyPem($p256dh);
        $subKey = openssl_pkey_get_public($subPubPem);
        if (!$subKey) throw new \RuntimeException('bad subscription pubkey');
        $shared = openssl_pkey_derive($subKey, $ephKey);
        if (!$shared) throw new \RuntimeException('ecdh derive failed');

        // 3) PRK = HKDF(salt=auth, ikm=shared, info="WebPush: info\x00" + p256dh + ephPub, len=32)
        $keyInfo = "WebPush: info\x00" . $p256dh . $ephPub;
        $prk = self::hkdf($shared, $auth, $keyInfo, 32);

        // 4) Salt para content encryption
        $salt = random_bytes(16);

        // 5) CEK y nonce
        $cek   = self::hkdf($prk, $salt, "Content-Encoding: aes128gcm\x00", 16);
        $nonce = self::hkdf($prk, $salt, "Content-Encoding: nonce\x00", 12);

        // 6) Plaintext + padding delimiter (0x02) — sin padding adicional para simplicidad
        $plainPadded = $plain . "\x02";

        // 7) AES-128-GCM
        $tag = '';
        $ct = openssl_encrypt($plainPadded, 'aes-128-gcm', $cek, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
        if ($ct === false) throw new \RuntimeException('encrypt failed');
        $ciphertext = $ct . $tag;  // GCM tag va al final

        // 8) Header aes128gcm: salt(16) + rs(4 big-endian) + idlen(1) + keyid(65)
        $rs = 4096;
        $body = $salt . pack('N', $rs) . chr(65) . $ephPub . $ciphertext;
        return $body;
    }

    // ---------- Helpers ----------------------------------------------------
    public static function generateVapidKeys(): array {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($key);
        openssl_pkey_export($key, $privPem);
        // Extract raw 32-byte private
        $priv = self::extractRawPrivFromPem($privPem);
        $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);
        $pub = "\x04" . $x . $y;
        return [
            'public'  => self::b64url($pub),
            'private' => self::b64url($priv),
        ];
    }

    private static function extractRawPrivFromPem(string $pem): string {
        // Parse minimal EC PRIVATE KEY DER to extract 32-byte private
        $b64 = preg_replace('/-----.*?-----|\s+/', '', $pem);
        $der = base64_decode($b64);
        // Find OCTET STRING of length 32 (0x04 0x20)
        $pos = 0;
        while ($pos < strlen($der) - 34) {
            if ($der[$pos] === "\x04" && $der[$pos + 1] === "\x20") {
                return substr($der, $pos + 2, 32);
            }
            $pos++;
        }
        throw new \RuntimeException('cant extract raw private');
    }

    private static function ecPrivateKeyPem(string $rawPriv, string $rawPub): string {
        // Build DER for EC PRIVATE KEY (SEC1)
        // SEQUENCE { INTEGER(1), OCTET STRING(priv), [0](OID secp256r1), [1](BIT STRING pub) }
        $oidSecp256r1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $inner = "\x02\x01\x01"                                          // INTEGER 1 (version)
               . "\x04\x20" . $rawPriv                                    // OCTET STRING private
               . "\xa0" . self::derLen(strlen($oidSecp256r1)) . $oidSecp256r1  // [0] curve OID
               . "\xa1" . self::derLen(strlen($rawPub) + 2) . "\x03" . self::derLen(strlen($rawPub) + 1) . "\x00" . $rawPub; // [1] BIT STRING pub
        $seq = "\x30" . self::derLen(strlen($inner)) . $inner;
        $pem = "-----BEGIN EC PRIVATE KEY-----\n"
             . chunk_split(base64_encode($seq), 64, "\n")
             . "-----END EC PRIVATE KEY-----\n";
        return $pem;
    }

    private static function ecPublicKeyPem(string $rawPub): string {
        // SubjectPublicKeyInfo for EC on secp256r1
        // SEQUENCE { SEQUENCE { OID ecPublicKey, OID secp256r1 }, BIT STRING pub }
        $oidEcPub = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $oidCurve = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $algo = "\x30" . self::derLen(strlen($oidEcPub) + strlen($oidCurve)) . $oidEcPub . $oidCurve;
        $bitStr = "\x03" . self::derLen(strlen($rawPub) + 1) . "\x00" . $rawPub;
        $spki = "\x30" . self::derLen(strlen($algo) + strlen($bitStr)) . $algo . $bitStr;
        return "-----BEGIN PUBLIC KEY-----\n"
             . chunk_split(base64_encode($spki), 64, "\n")
             . "-----END PUBLIC KEY-----\n";
    }

    private static function derLen(int $len): string {
        if ($len < 128) return chr($len);
        $b = '';
        while ($len > 0) { $b = chr($len & 0xff) . $b; $len >>= 8; }
        return chr(0x80 | strlen($b)) . $b;
    }

    private static function derToRawEcSig(string $der): string {
        // DER: SEQUENCE { INTEGER r, INTEGER s } → raw R(32) || S(32)
        if ($der[0] !== "\x30") throw new \RuntimeException('bad der sig');
        $pos = 2;
        if (ord($der[1]) & 0x80) $pos += (ord($der[1]) & 0x7f);
        // R
        if ($der[$pos] !== "\x02") throw new \RuntimeException('bad r');
        $rLen = ord($der[$pos + 1]);
        $r = substr($der, $pos + 2, $rLen);
        $pos += 2 + $rLen;
        // S
        if ($der[$pos] !== "\x02") throw new \RuntimeException('bad s');
        $sLen = ord($der[$pos + 1]);
        $s = substr($der, $pos + 2, $sLen);
        // Strip leading zeros / pad to 32
        $r = str_pad(ltrim($r, "\x00"), 32, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), 32, "\x00", STR_PAD_LEFT);
        return $r . $s;
    }

    private static function hkdf(string $ikm, string $salt, string $info, int $length): string {
        // HKDF-SHA256
        $prk = hash_hmac('sha256', $ikm, $salt, true);
        $t = '';
        $out = '';
        $counter = 1;
        while (strlen($out) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($counter), $prk, true);
            $out .= $t;
            $counter++;
        }
        return substr($out, 0, $length);
    }

    private static function getAudience(string $endpoint): string {
        $p = parse_url($endpoint);
        return ($p['scheme'] ?? 'https') . '://' . ($p['host'] ?? '');
    }

    public static function b64url(string $s): string {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }
    public static function b64urlDec(string $s): string {
        $pad = (4 - strlen($s) % 4) % 4;
        return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', $pad));
    }
}
