-- Add show_text_content column to protocols
ALTER TABLE protocols ADD COLUMN show_text_content TINYINT(1) NOT NULL DEFAULT 0;

-- Add translations
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'show_text_content', 'Show text content on client page'),
('en', 'protocols', 'qr_code_format_text', 'Simple Text'),
('ru', 'protocols', 'show_text_content', 'Показывать текстовое содержимое на странице клиента'),
('ru', 'protocols', 'qr_code_format_text', 'Простой текст')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
