-- Add translations for monitoring UI elements

-- Check if translations table has old structure and migrate it
DROP PROCEDURE IF EXISTS migrate_translations;
DELIMITER $$
CREATE PROCEDURE migrate_translations()
BEGIN
    DECLARE old_structure INT DEFAULT 0;
    DECLARE new_structure INT DEFAULT 0;
    
    -- Check if old column 'translation_key' exists
    SELECT COUNT(*) INTO old_structure
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'translations'
    AND COLUMN_NAME = 'translation_key';
    
    -- Check if new column 'key_name' exists
    SELECT COUNT(*) INTO new_structure
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'translations'
    AND COLUMN_NAME = 'key_name';
    
    -- If old structure exists and new doesn't, migrate data
    IF old_structure > 0 AND new_structure = 0 THEN
        -- Create temporary table with new structure
        CREATE TABLE translations_new (
            id INT AUTO_INCREMENT PRIMARY KEY,
            locale VARCHAR(5) NOT NULL,
            category VARCHAR(50) NOT NULL,
            key_name VARCHAR(100) NOT NULL,
            translation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_translation (locale, category, key_name),
            INDEX idx_locale (locale)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        
        -- Migrate data from old structure to new
        INSERT INTO translations_new (locale, category, key_name, translation, created_at)
        SELECT 
            language_code as locale,
            SUBSTRING_INDEX(translation_key, '.', 1) as category,
            SUBSTRING_INDEX(translation_key, '.', -1) as key_name,
            translation_value as translation,
            created_at
        FROM translations;
        
        -- Replace old table with new
        DROP TABLE translations;
        RENAME TABLE translations_new TO translations;
    END IF;
    
    -- If table doesn't exist at all, create it with new structure
    IF old_structure = 0 AND new_structure = 0 THEN
        CREATE TABLE IF NOT EXISTS translations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            locale VARCHAR(5) NOT NULL,
            category VARCHAR(50) NOT NULL,
            key_name VARCHAR(100) NOT NULL,
            translation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_translation (locale, category, key_name),
            INDEX idx_locale (locale)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END$$
DELIMITER ;

CALL migrate_translations();
DROP PROCEDURE migrate_translations;

-- Insert new translations (will skip duplicates)
INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES 
-- Speed
('en', 'common', 'speed', 'Speed'),
('ru', 'common', 'speed', 'Скорость'),
('es', 'common', 'speed', 'Velocidad'),
('de', 'common', 'speed', 'Geschwindigkeit'),
('fr', 'common', 'speed', 'Vitesse'),
('zh', 'common', 'speed', '速度'),

-- Metrics
('en', 'common', 'metrics', 'Metrics'),
('ru', 'common', 'metrics', 'Метрики'),
('es', 'common', 'metrics', 'Métricas'),
('de', 'common', 'metrics', 'Metriken'),
('fr', 'common', 'metrics', 'Métriques'),
('zh', 'common', 'metrics', '指标'),

-- Server Info
('en', 'servers', 'server_info', 'Server Info'),
('ru', 'servers', 'server_info', 'Информация о сервере'),
('es', 'servers', 'server_info', 'Información del servidor'),
('de', 'servers', 'server_info', 'Serverinformationen'),
('fr', 'servers', 'server_info', 'Informations sur le serveur'),
('zh', 'servers', 'server_info', '服务器信息'),

-- Status
('en', 'common', 'status', 'Status'),
('ru', 'common', 'status', 'Статус'),
('es', 'common', 'status', 'Estado'),
('de', 'common', 'status', 'Status'),
('fr', 'common', 'status', 'Statut'),
('zh', 'common', 'status', '状态'),

-- Client Configuration
('en', 'clients', 'configuration', 'Client Configuration'),
('ru', 'clients', 'configuration', 'Конфигурация клиента'),
('es', 'clients', 'configuration', 'Configuración del cliente'),
('de', 'clients', 'configuration', 'Client-Konfiguration'),
('fr', 'clients', 'configuration', 'Configuration du client'),
('zh', 'clients', 'configuration', '客户端配置'),

-- Traffic Statistics
('en', 'clients', 'traffic_stats', 'Traffic Statistics'),
('ru', 'clients', 'traffic_stats', 'Статистика трафика'),
('es', 'clients', 'traffic_stats', 'Estadísticas de tráfico'),
('de', 'clients', 'traffic_stats', 'Traffic-Statistiken'),
('fr', 'clients', 'traffic_stats', 'Statistiques de trafic'),
('zh', 'clients', 'traffic_stats', '流量统计'),

-- Uploaded
('en', 'common', 'uploaded', 'Uploaded'),
('ru', 'common', 'uploaded', 'Отправлено'),
('es', 'common', 'uploaded', 'Subido'),
('de', 'common', 'uploaded', 'Hochgeladen'),
('fr', 'common', 'uploaded', 'Envoyé'),
('zh', 'common', 'uploaded', '上传'),

-- Downloaded
('en', 'common', 'downloaded', 'Downloaded'),
('ru', 'common', 'downloaded', 'Получено'),
('es', 'common', 'downloaded', 'Descargado'),
('de', 'common', 'downloaded', 'Heruntergeladen'),
('fr', 'common', 'downloaded', 'Reçu'),
('zh', 'common', 'downloaded', '下载'),

-- Total
('en', 'common', 'total', 'Total'),
('ru', 'common', 'total', 'Всего'),
('es', 'common', 'total', 'Total'),
('de', 'common', 'total', 'Gesamt'),
('fr', 'common', 'total', 'Total'),
('zh', 'common', 'total', '总计'),

-- Created
('en', 'common', 'created', 'Created'),
('ru', 'common', 'created', 'Создан'),
('es', 'common', 'created', 'Creado'),
('de', 'common', 'created', 'Erstellt'),
('fr', 'common', 'created', 'Créé'),
('zh', 'common', 'created', '创建时间'),

-- IP Address
('en', 'common', 'ip_address', 'IP Address'),
('ru', 'common', 'ip_address', 'IP-адрес'),
('es', 'common', 'ip_address', 'Dirección IP'),
('de', 'common', 'ip_address', 'IP-Adresse'),
('fr', 'common', 'ip_address', 'Adresse IP'),
('zh', 'common', 'ip_address', 'IP地址')

ON DUPLICATE KEY UPDATE translation=VALUES(translation);
