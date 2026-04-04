-- Ensure clients.connection_instructions exists in all locales used by UI.
-- Without this key, client view heading may be missing or fallback text can appear inconsistent.

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'clients', 'connection_instructions', 'Connection Instructions'),
('ru', 'clients', 'connection_instructions', 'Инструкции по подключению'),
('es', 'clients', 'connection_instructions', 'Instrucciones de conexión'),
('de', 'clients', 'connection_instructions', 'Verbindungsanweisungen'),
('fr', 'clients', 'connection_instructions', 'Instructions de connexion'),
('zh', 'clients', 'connection_instructions', '连接说明')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
