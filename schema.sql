-- Baby Tracker schema
-- Idempotente: CREATE TABLE IF NOT EXISTS. ALTERs se manejan en install.php.

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  email_verified TINYINT(1) NOT NULL DEFAULT 0,
  password_hash VARCHAR(255) NOT NULL,
  totp_secret_encrypted VARBINARY(255) NULL,
  totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY unique_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_verifications (
  user_id INT UNSIGNED NOT NULL,
  code VARCHAR(10) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  INDEX code_idx (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS password_resets (
  token VARCHAR(64) NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (token),
  INDEX user_idx (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  credential_id VARBINARY(255) NOT NULL,
  public_key TEXT NOT NULL,
  sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  device_name VARCHAR(100) NULL,
  transports VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  PRIMARY KEY (id),
  UNIQUE KEY unique_credential (credential_id),
  INDEX user_idx (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_attempts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(45) NOT NULL,
  email VARCHAR(255) NULL,
  success TINYINT(1) NOT NULL DEFAULT 0,
  reason VARCHAR(50) NULL,
  action VARCHAR(20) NOT NULL DEFAULT 'login',
  attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX ip_time_idx (ip, attempted_at),
  INDEX email_time_idx (email, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS babies (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  owner_id INT UNSIGNED NOT NULL,
  name VARCHAR(100) NOT NULL,
  birthdate DATE NULL,
  sex ENUM('girl','boy','other') NOT NULL DEFAULT 'other',
  emoji VARCHAR(8) NOT NULL DEFAULT '👶',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX owner_idx (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS baby_shares (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  baby_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  role ENUM('viewer','editor','admin') NOT NULL DEFAULT 'editor',
  invited_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  accepted_at TIMESTAMP NULL,
  PRIMARY KEY (id),
  UNIQUE KEY unique_share (baby_id, user_id),
  INDEX baby_idx (baby_id),
  INDEX user_idx (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS invitations (
  token VARCHAR(64) NOT NULL,
  baby_id INT UNSIGNED NOT NULL,
  inviter_id INT UNSIGNED NOT NULL,
  invitee_email VARCHAR(255) NULL,
  role ENUM('viewer','editor','admin') NOT NULL DEFAULT 'editor',
  expires_at TIMESTAMP NOT NULL,
  accepted_at TIMESTAMP NULL,
  accepted_by INT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (token),
  INDEX baby_idx (baby_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS entries (
  baby_id INT UNSIGNED NOT NULL,
  data_key VARCHAR(50) NOT NULL,
  data_json LONGTEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (baby_id, data_key),
  INDEX baby_idx (baby_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS photos (
  id VARCHAR(64) NOT NULL,
  baby_id INT UNSIGNED NOT NULL,
  record_type VARCHAR(30) NULL,
  record_id BIGINT NULL,
  mime VARCHAR(50) NOT NULL,
  name VARCHAR(200) NULL,
  data LONGBLOB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX baby_idx (baby_id),
  INDEX record_idx (baby_id, record_type, record_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
