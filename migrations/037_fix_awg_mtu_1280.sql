-- Fix AmneziaWG MTU to 1280 for better compatibility
-- This resolves connection issues with PPPoE, mobile networks, and tunnels
UPDATE protocols SET 
  install_script = REPLACE(install_script, 'MTU=${MTU:-1420}', 'MTU=${MTU:-1280}')
WHERE slug = 'amnezia-wg-advanced';
