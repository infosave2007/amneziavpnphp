-- Backfill XRay server_port from extras.result keys produced by set -x
UPDATE server_protocols sp
JOIN protocols p ON p.id = sp.protocol_id
SET sp.config_data = JSON_SET(sp.config_data, '$.server_port', JSON_EXTRACT(sp.config_data, '$.extras.result."+_xray_port"')),
    sp.applied_at = NOW()
WHERE p.slug = 'xray-vless'
  AND (
    JSON_EXTRACT(sp.config_data, '$.server_port') IS NULL OR
    JSON_UNQUOTE(JSON_EXTRACT(sp.config_data, '$.server_port')) = ''
  )
  AND JSON_EXTRACT(sp.config_data, '$.extras.result."+_xray_port"') IS NOT NULL;

UPDATE server_protocols sp
JOIN protocols p ON p.id = sp.protocol_id
SET sp.config_data = JSON_SET(sp.config_data, '$.server_port', JSON_EXTRACT(sp.config_data, '$.extras.result.xray_port')),
    sp.applied_at = NOW()
WHERE p.slug = 'xray-vless'
  AND (
    JSON_EXTRACT(sp.config_data, '$.server_port') IS NULL OR
    JSON_UNQUOTE(JSON_EXTRACT(sp.config_data, '$.server_port')) = ''
  )
  AND JSON_EXTRACT(sp.config_data, '$.extras.result.xray_port') IS NOT NULL;