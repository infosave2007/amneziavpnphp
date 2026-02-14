-- Add missing translations for protocol management UI (EN/RU)
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'management', 'Protocol Management'),
('ru', 'protocols', 'management', 'Управление протоколами'),
('en', 'protocols', 'management_description', 'Configure and manage VPN protocols'),
('ru', 'protocols', 'management_description', 'Настройка и управление VPN-протоколами'),
('en', 'common', 'active', 'Active'),
('ru', 'common', 'active', 'Активный'),
('en', 'common', 'inactive', 'Inactive'),
('ru', 'common', 'inactive', 'Неактивный'),
('en', 'protocols', 'add_protocol', 'Add Protocol'),
('ru', 'protocols', 'add_protocol', 'Добавить протокол'),
('en', 'common', 'settings', 'Settings'),
('ru', 'common', 'settings', 'Настройки'),
('en', 'protocols', 'available_protocols', 'Available Protocols'),
('ru', 'protocols', 'available_protocols', 'Доступные протоколы'),
('en', 'protocols', 'search_protocols', 'Search protocols'),
('ru', 'protocols', 'search_protocols', 'Поиск протоколов'),
('en', 'protocols', 'all_protocols', 'All Protocols'),
('ru', 'protocols', 'all_protocols', 'Все протоколы'),
('en', 'protocols', 'active_only', 'Active only'),
('ru', 'protocols', 'active_only', 'Только активные'),
('en', 'protocols', 'with_ai_generations', 'With AI generations'),
('ru', 'protocols', 'with_ai_generations', 'С AI-генерациями')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

-- Hide protocols that should not be published
UPDATE protocols
SET is_active = 0
WHERE slug IN ('cloak', 'openvpn', 'shadowsocks', 'wireguard', 'wireguard-standard')
	OR name IN ('Cloak', 'OpenVPN', 'Shadowsocks', 'WireGuard', 'WireGuard Standard');
