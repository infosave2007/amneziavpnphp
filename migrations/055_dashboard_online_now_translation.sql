-- Add translation for dashboard.online_now
INSERT INTO translations (`locale`, `category`, `key_name`, `translation`) VALUES
('en', 'dashboard', 'online_now', 'Online Now'),
('ru', 'dashboard', 'online_now', 'Сейчас онлайн'),
('es', 'dashboard', 'online_now', 'En línea ahora'),
('de', 'dashboard', 'online_now', 'Jetzt online'),
('fr', 'dashboard', 'online_now', 'En ligne maintenant'),
('zh', 'dashboard', 'online_now', '当前在线')
ON DUPLICATE KEY UPDATE `translation` = VALUES(`translation`);
