# API Usage Examples

## Authentication

### Get JWT Token
```bash
curl -X POST http://localhost:8082/api/auth/token \
  -d "email=admin@amnez.ia&password=admin123"
```

Response:
```json
{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "type": "Bearer",
  "expires_in": 2592000
}
```

## Protocols

### List Active Protocols (for JWT API clients)
```bash
curl -X GET http://localhost:8082/api/protocols/active \
  -H "Authorization: Bearer $TOKEN"
```

Example response:
```json
{
  "success": true,
  "protocols": [
    {"id": 11, "slug": "awg2", "name": "AmneziaWG 2.0"},
    {"id": 13, "slug": "aivpn", "name": "AIVPN"},
    {"id": 12, "slug": "mtproxy", "name": "MTProxy (Telegram)"}
  ]
}
```

### Install Protocol on Server
```bash
curl -X POST http://localhost:8082/api/servers/1/protocols/install \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"protocol_id":11}'
```

## Clients

### Create Client with QR Code
```bash
TOKEN="your-jwt-token"

curl -X POST http://localhost:8082/api/clients/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": 1,
    "name": "My Phone"
  }'
```

Response:
```json
{
  "success": true,
  "client": {
    "id": 1,
    "name": "My Phone",
    "server_id": 1,
    "client_ip": "10.8.1.1",
    "status": "active",
    "created_at": "2025-11-07 12:00:00",
    "config": "[Interface]\nPrivateKey = ...\n...",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
  }
}
```

The `qr_code` field contains a data URI that can be used directly in HTML:
```html
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." alt="QR Code" />
```

### Get Client QR Code
```bash
curl -X GET http://localhost:8082/api/clients/1/qr \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "success": true,
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "client_name": "My Phone"
}
```

### Get Client Details with Stats, Config and QR
```bash
curl -X GET http://localhost:8082/api/clients/1/details \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "success": true,
  "client": {
    "id": 1,
    "name": "My Phone",
    "server_id": 1,
    "client_ip": "10.8.1.1",
    "status": "active",
    "created_at": "2025-11-07 12:00:00",
    "stats": {
      "sent": "1.23 GB",
      "received": "456.78 MB",
      "total": "1.68 GB",
      "last_seen": "Online",
      "is_online": true
    },
    "bytes_sent": 1320000000,
    "bytes_received": 478800000,
    "last_handshake": "2025-11-07 12:30:00",
    "config": "[Interface]\nPrivateKey = ...\n...",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
  }
}
```

## Servers

### List Servers
```bash
curl -X GET http://localhost:8082/api/servers \
  -H "Authorization: Bearer $TOKEN"
```

### Create Server
```bash
curl -X POST http://localhost:8082/api/servers/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "US Server",
    "host": "192.168.1.100",
    "port": 22,
    "username": "root",
    "password": "your-password"
  }'
```

### Get Server Clients
```bash
curl -X GET http://localhost:8082/api/servers/1/clients \
  -H "Authorization: Bearer $TOKEN"
```

## Client Management

### Revoke Client
```bash
curl -X POST http://localhost:8082/api/clients/1/revoke \
  -H "Authorization: Bearer $TOKEN"
```

### Restore Client
```bash
curl -X POST http://localhost:8082/api/clients/1/restore \
  -H "Authorization: Bearer $TOKEN"
```

### Delete Client
```bash
curl -X DELETE http://localhost:8082/api/clients/1/delete \
  -H "Authorization: Bearer $TOKEN"
```

## Integration Examples

### Python Example
```python
import requests
import base64
from io import BytesIO
from PIL import Image

# Get token
response = requests.post('http://localhost:8082/api/auth/token', 
    data={'email': 'admin@amnez.ia', 'password': 'admin123'})
token = response.json()['token']

headers = {'Authorization': f'Bearer {token}'}

# Create client
client_data = {
    'server_id': 1,
    'name': 'My Phone'
}
response = requests.post('http://localhost:8082/api/clients/create',
    json=client_data, headers=headers)

result = response.json()
qr_code_data_uri = result['client']['qr_code']

# Save QR code as image
qr_base64 = qr_code_data_uri.split(',')[1]
qr_bytes = base64.b64decode(qr_base64)
image = Image.open(BytesIO(qr_bytes))
image.save('qr_code.png')

print(f"Client created: {result['client']['name']}")
print(f"QR code saved to qr_code.png")
```

### JavaScript/Node.js Example
```javascript
const axios = require('axios');
const fs = require('fs');

// Get token
const authResponse = await axios.post('http://localhost:8082/api/auth/token', 
  'email=admin@amnez.ia&password=admin123');
const token = authResponse.data.token;

const headers = { 'Authorization': `Bearer ${token}` };

// Create client
const clientData = {
  server_id: 1,
  name: 'My Phone'
};

const response = await axios.post('http://localhost:8082/api/clients/create',
  clientData, { headers });

const qrCodeDataUri = response.data.client.qr_code;

// Save QR code as image
const base64Data = qrCodeDataUri.split(',')[1];
fs.writeFileSync('qr_code.png', base64Data, 'base64');

console.log(`Client created: ${response.data.client.name}`);
console.log('QR code saved to qr_code.png');
```

### Display QR Code in Web Page
```html
<!DOCTYPE html>
<html>
<head>
    <title>VPN Client QR Code</title>
</head>
<body>
    <h1>Scan this QR code with Amnezia VPN app</h1>
    <div id="qr-container"></div>

    <script>
        async function loadQRCode() {
            // Get token
            const formData = new URLSearchParams();
            formData.append('email', 'admin@amnez.ia');
            formData.append('password', 'admin123');
            
            const authResponse = await fetch('http://localhost:8082/api/auth/token', {
                method: 'POST',
                body: formData
            });
            const authData = await authResponse.json();
            const token = authData.token;

            // Create client
            const response = await fetch('http://localhost:8082/api/clients/create', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    server_id: 1,
                    name: 'Web Client'
                })
            });

            const data = await response.json();
            
            // Display QR code
            const img = document.createElement('img');
            img.src = data.client.qr_code;
            img.alt = 'VPN Client QR Code';
            img.style.width = '300px';
            img.style.height = '300px';
            
            document.getElementById('qr-container').appendChild(img);
        }

        loadQRCode();
    </script>
</body>
</html>
```
