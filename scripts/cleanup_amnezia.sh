#!/bin/bash
# Universal cleanup script for all Amnezia containers
# Based on remove_all_containers.sh from amnezia-client
# Usage: ./cleanup_amnezia.sh

set -euo pipefail

echo "========================================="
echo "Amnezia VPN - Complete Cleanup Script"
echo "========================================="
echo ""
echo "WARNING: This will remove ALL Amnezia containers, images, and data!"
echo "Press Ctrl+C to cancel, or Enter to continue..."
read -r

echo ""
echo "Step 1: Stopping all Amnezia containers..."
CONTAINERS=$(docker ps -a | grep amnezia | awk '{print $1}' || true)
if [ -n "$CONTAINERS" ]; then
    echo "$CONTAINERS" | xargs docker stop || true
    echo "✓ Containers stopped"
else
    echo "✓ No running containers found"
fi

echo ""
echo "Step 2: Removing all Amnezia containers..."
CONTAINERS=$(docker ps -a | grep amnezia | awk '{print $1}' || true)
if [ -n "$CONTAINERS" ]; then
    echo "$CONTAINERS" | xargs docker rm -fv || true
    echo "✓ Containers removed"
else
    echo "✓ No containers to remove"
fi

echo ""
echo "Step 3: Removing all Amnezia images..."
IMAGES=$(docker images -a | grep amnezia | awk '{print $3}' || true)
if [ -n "$IMAGES" ]; then
    echo "$IMAGES" | xargs docker rmi -f || true
    echo "✓ Images removed"
else
    echo "✓ No images to remove"
fi

echo ""
echo "Step 4: Removing Amnezia DNS network..."
docker network rm amnezia-dns-net 2>/dev/null && echo "✓ Network removed" || echo "✓ Network not found"

echo ""
echo "Step 5: Removing Amnezia data directory..."
if [ -d "/opt/amnezia" ]; then
    rm -rf /opt/amnezia
    echo "✓ Data directory removed"
else
    echo "✓ Data directory not found"
fi

echo ""
echo "========================================="
echo "Cleanup completed successfully!"
echo "========================================="
echo ""
echo "Summary:"
echo "- All Amnezia containers stopped and removed"
echo "- All Amnezia Docker images removed"
echo "- Amnezia DNS network removed"
echo "- All configuration data removed from /opt/amnezia"
echo ""
