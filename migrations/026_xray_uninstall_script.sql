-- Set uninstall script for XRay VLESS protocol
UPDATE protocols
SET uninstall_script = '#!/bin/bash\n\nset -euo pipefail\nset -x\n\nCONTAINER_NAME="${SERVER_CONTAINER:-${CONTAINER_NAME:-amnezia-xray}}"\n\ndocker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true\nrm -rf /opt/amnezia/xray || true\n\necho "Uninstalled: ${CONTAINER_NAME}"\n'
WHERE slug = 'xray-vless';