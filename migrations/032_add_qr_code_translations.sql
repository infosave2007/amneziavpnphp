-- Add translations for QR code template UI
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'qr_code_template', 'QR Code Template'),
('en', 'protocols', 'qr_code_format', 'QR Code Format'),
('en', 'protocols', 'qr_code_format_help', 'Select the format for the QR code payload. "Amnezia Compressed" uses the legacy Qt/QDataStream format. "Raw Content" uses the template output directly.'),
('en', 'protocols', 'qr_code_template_help', 'Template for the QR code payload. Use {{last_config_json}} to include the full configuration as a JSON object.'),
('en', 'protocols', 'variable_last_config_json_help', 'Full configuration as a JSON object (required for Amnezia format)'),
('en', 'protocols', 'plus_all_output_variables', 'Plus all variables from the Output Template section'),
('en', 'ai', 'prompt_placeholder_qr_template', 'Describe how the QR code payload should be structured (e.g., "Standard WireGuard config format" or "JSON with specific fields")')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
