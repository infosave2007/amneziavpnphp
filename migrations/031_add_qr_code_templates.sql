ALTER TABLE protocols ADD COLUMN qr_code_template MEDIUMTEXT DEFAULT NULL;
ALTER TABLE protocols ADD COLUMN qr_code_format VARCHAR(50) DEFAULT 'amnezia_compressed';

-- Update AmneziaWG and WireGuard
UPDATE protocols SET qr_code_template = '{
    "containers": [
        {
            "awg": {
                "H1": "{{H1}}",
                "H2": "{{H2}}",
                "H3": "{{H3}}",
                "H4": "{{H4}}",
                "Jc": "{{Jc}}",
                "Jmax": "{{Jmax}}",
                "Jmin": "{{Jmin}}",
                "S1": "{{S1}}",
                "S2": "{{S2}}",
                "last_config": {{last_config_json}},
                "port": "{{port}}",
                "transport_proto": "udp"
            },
            "container": "amnezia-awg"
        }
    ],
    "defaultContainer": "amnezia-awg",
    "description": "{{description}}",
    "dns1": "{{dns1}}",
    "dns2": "{{dns2}}",
    "hostName": "{{hostName}}"
}' WHERE slug IN ('amnezia-wg', 'wireguard', 'amnezia-wg-advanced');

-- Update XRay
UPDATE protocols SET qr_code_template = '{
    "containers": [
        {
            "container": "amnezia-xray",
            "xray": {
                "last_config": {{last_config_json}},
                "port": "{{port}}",
                "transport_proto": "tcp"
            }
        }
    ],
    "defaultContainer": "amnezia-xray",
    "description": "{{description}}",
    "dns1": "1.1.1.1",
    "dns2": "1.0.0.1",
    "hostName": "{{hostName}}"
}' WHERE slug LIKE '%xray%';
