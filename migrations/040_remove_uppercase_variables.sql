-- Remove fully uppercase variable outputs from AmneziaWG install script
-- Keep only Jc, Jmin, Jmax format (first letter uppercase)
UPDATE protocols SET 
  install_script = REPLACE(
    REPLACE(
      REPLACE(
        install_script, 
        'echo "Variable: JC=${JC:-5}"', 
        ''
      ), 
      'echo "Variable: JMIN=${JMIN:-100}"', 
      ''
    ), 
    'echo "Variable: JMAX=${JMAX:-200}"', 
    ''
  )
WHERE slug = 'amnezia-wg-advanced';
