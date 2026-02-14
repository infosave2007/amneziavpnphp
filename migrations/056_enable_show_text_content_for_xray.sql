-- Enable text content display by default on client page for XRay VLESS
UPDATE protocols
SET show_text_content = 1
WHERE slug = 'xray-vless'
  AND COALESCE(show_text_content, 0) <> 1;
