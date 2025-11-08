# Import Examples

This directory contains example backup files from different VPN panels that can be imported into Amnezia VPN Panel.

## wg-easy-backup-example.json

Example backup file from wg-easy panel (db.json format).

**Features:**
- Contains 3 clients with different configurations
- Includes public/private keys and pre-shared keys
- Shows enabled and disabled clients
- Preserves original IP addresses

**How to get from wg-easy:**
```bash
# SSH into your wg-easy server
ssh user@your-server

# Copy the database file
docker cp wg-easy:/app/data/db.json ./wg-easy-backup.json
```

## 3x-ui-backup-example.json

Example export file from 3x-ui panel.

**Features:**
- Contains 3 clients with traffic statistics
- Includes expiration dates and traffic limits
- Shows enabled and disabled clients
- Contains server settings (port, interface, MTU)

**How to get from 3x-ui:**
1. Login to your 3x-ui panel
2. Go to Settings
3. Click "Export" button
4. Save the JSON file

## Import Process

1. **Create New Server:**
   - Go to "Servers" → "Add Server"
   - Fill in SSH connection details
   - Check "Import from existing panel"

2. **Select Panel Type:**
   - Choose "wg-easy" or "3x-ui"
   - Upload your backup file

3. **Deploy:**
   - Click "Create Server"
   - Wait for deployment
   - Clients will be imported automatically

## What Gets Imported

### From wg-easy:
- ✅ Client names
- ✅ Public/private keys
- ✅ Pre-shared keys
- ✅ IP addresses
- ✅ Enabled/disabled status
- ✅ Creation timestamps

### From 3x-ui:
- ✅ Client names (from email field)
- ✅ Traffic limits (totalGB)
- ✅ Expiration dates
- ✅ Enabled/disabled status
- ⚠️ Keys will be auto-generated (3x-ui doesn't export them)
- ⚠️ IP addresses will be auto-assigned

## Troubleshooting

**Import fails with "Invalid JSON format":**
- Ensure your backup file is valid JSON
- Check that it matches the expected format for your panel type

**Some clients not imported:**
- Check import history in the panel
- Review error messages for specific clients
- Ensure client names are unique

**Keys not working after import:**
- wg-easy imports preserve original keys
- 3x-ui imports generate new keys (clients need new configs)
