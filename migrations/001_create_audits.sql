-- Migration: create audits table
-- Table name follows GORM default for model `Audit` => `audits`

CREATE TABLE IF NOT EXISTS `audits` (
  `id` CHAR(36) NOT NULL,
  `trace_id` CHAR(32) NOT NULL,
  `client_id` VARCHAR(128) DEFAULT NULL,
  `user_id` VARCHAR(64) DEFAULT NULL,
  `ip` VARCHAR(45) DEFAULT NULL,
  `ua` VARCHAR(512) DEFAULT NULL,
  `function` VARCHAR(128) DEFAULT NULL,
  `finish_at` DATETIME DEFAULT NULL,
  `result_code` INT DEFAULT NULL,
  `message` TEXT,
  PRIMARY KEY (`id`),
  KEY `idx_audits_trace_id` (`trace_id`),
  KEY `idx_audits_client_id` (`client_id`),
  KEY `idx_audits_user_id` (`user_id`),
  KEY `idx_audits_finish_at` (`finish_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

