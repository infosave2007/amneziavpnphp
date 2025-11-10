-- Migration: Add LDAP translations (English and Russian)
-- Date: 2025-11-10

-- English translations
INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES
('en', 'ldap', 'settings', 'LDAP Settings'),
('en', 'ldap', 'enable_ldap_auth', 'Enable LDAP Authentication'),
('en', 'ldap', 'enable_description', 'Allow users to login using LDAP/Active Directory credentials'),
('en', 'ldap', 'host', 'LDAP Host'),
('en', 'ldap', 'port', 'Port'),
('en', 'ldap', 'use_tls', 'Use TLS/SSL'),
('en', 'ldap', 'base_dn', 'Base DN'),
('en', 'ldap', 'base_dn_description', 'The base distinguished name for LDAP searches (e.g., dc=example,dc=com)'),
('en', 'ldap', 'bind_dn', 'Bind DN'),
('en', 'ldap', 'bind_dn_description', 'The distinguished name of the service account to bind with'),
('en', 'ldap', 'bind_password', 'Bind Password'),
('en', 'ldap', 'user_search_filter', 'User Search Filter'),
('en', 'ldap', 'user_search_filter_description', 'LDAP filter to search for users. %s will be replaced with username'),
('en', 'ldap', 'group_search_filter', 'Group Search Filter'),
('en', 'ldap', 'sync_interval', 'Sync Interval (minutes)'),
('en', 'ldap', 'sync_interval_description', 'How often to automatically synchronize users from LDAP'),
('en', 'ldap', 'test_connection', 'Test Connection'),
('en', 'ldap', 'testing', 'Testing'),
('en', 'ldap', 'connection_test_failed', 'Connection test failed'),
('en', 'ldap', 'group_mappings', 'LDAP Group Mappings'),
('en', 'ldap', 'group', 'LDAP Group'),
('en', 'ldap', 'role', 'Panel Role'),
('en', 'ldap', 'description', 'Description');

-- Russian translations
INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES
('ru', 'ldap', 'settings', 'Настройки LDAP'),
('ru', 'ldap', 'enable_ldap_auth', 'Включить LDAP аутентификацию'),
('ru', 'ldap', 'enable_description', 'Разрешить пользователям входить используя учетные данные LDAP/Active Directory'),
('ru', 'ldap', 'host', 'LDAP Хост'),
('ru', 'ldap', 'port', 'Порт'),
('ru', 'ldap', 'use_tls', 'Использовать TLS/SSL'),
('ru', 'ldap', 'base_dn', 'Base DN'),
('ru', 'ldap', 'base_dn_description', 'Базовое отличительное имя для поиска в LDAP (например, dc=example,dc=com)'),
('ru', 'ldap', 'bind_dn', 'Bind DN'),
('ru', 'ldap', 'bind_dn_description', 'Отличительное имя служебной учетной записи для подключения'),
('ru', 'ldap', 'bind_password', 'Пароль подключения'),
('ru', 'ldap', 'user_search_filter', 'Фильтр поиска пользователей'),
('ru', 'ldap', 'user_search_filter_description', 'LDAP фильтр для поиска пользователей. %s будет заменен на имя пользователя'),
('ru', 'ldap', 'group_search_filter', 'Фильтр поиска групп'),
('ru', 'ldap', 'sync_interval', 'Интервал синхронизации (минуты)'),
('ru', 'ldap', 'sync_interval_description', 'Как часто автоматически синхронизировать пользователей из LDAP'),
('ru', 'ldap', 'test_connection', 'Тест подключения'),
('ru', 'ldap', 'testing', 'Тестирование'),
('ru', 'ldap', 'connection_test_failed', 'Тест подключения не удался'),
('ru', 'ldap', 'group_mappings', 'Связи групп LDAP'),
('ru', 'ldap', 'group', 'Группа LDAP'),
('ru', 'ldap', 'role', 'Роль в панели'),
('ru', 'ldap', 'description', 'Описание');

-- Common translations for buttons
INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES
('en', 'common', 'save', 'Save'),
('en', 'common', 'cancel', 'Cancel'),
('ru', 'common', 'save', 'Сохранить'),
('ru', 'common', 'cancel', 'Отмена');
