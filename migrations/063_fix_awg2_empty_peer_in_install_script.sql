-- Remove invalid empty peer block from AWG2 install script.
-- The old script generated wg0.conf with:
--   [Peer]
--   PublicKey =
-- which causes awg setconf parse errors and restart loops.

UPDATE protocols
SET install_script = REPLACE(
  install_script,
  '\n[Peer]\nPublicKey = \nPresharedKey = $PRESHARED_KEY\nAllowedIPs = 10.8.1.2/32\n',
  '\n'
)
WHERE slug = 'awg2'
  AND install_script LIKE '%[Peer]%PublicKey = %PresharedKey = $PRESHARED_KEY%AllowedIPs = 10.8.1.2/32%';
