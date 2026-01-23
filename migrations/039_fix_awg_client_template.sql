-- Fix AmneziaWG client config template: add MTU and use capital letter variables
UPDATE protocols SET 
  output_template = '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = {{dns_servers}}
MTU = 1280
Jc = {{Jc}}
Jmin = {{Jmin}}
Jmax = {{Jmax}}
S1 = {{S1}}
S2 = {{S2}}
H1 = {{H1}}
H2 = {{H2}}
H3 = {{H3}}
H4 = {{H4}}

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25'
WHERE slug = 'amnezia-wg-advanced';

-- Create capital letter variables that map to lowercase ones
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'Jc', 'number', '5', 'Junk packet count', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='Jc');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'Jmin', 'number', '100', 'Minimum junk packet size', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='Jmin');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'Jmax', 'number', '200', 'Maximum junk packet size', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='Jmax');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'S1', 'number', '50', 'Junk packet size 1', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='S1');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'S2', 'number', '100', 'Junk packet size 2', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='S2');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'H1', 'number', '1', 'Obfuscation header 1', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='H1');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'H2', 'number', '2', 'Obfuscation header 2', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='H2');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'H3', 'number', '3', 'Obfuscation header 3', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='H3');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'H4', 'number', '4', 'Obfuscation header 4', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='H4');
