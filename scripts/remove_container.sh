#!/bin/bash
# Remove single Amnezia container
# Based on remove_container.sh from amnezia-client
# Usage: ./remove_container.sh <container_name>

set -euo pipefail

if [ $# -eq 0 ]; then
    echo "Usage: $0 <container_name>"
    echo "Example: $0 amnezia-awg"
    exit 1
fi

CONTAINER_NAME="$1"

echo "Removing Amnezia container: $CONTAINER_NAME"
echo ""

# Stop the container
echo "Stopping container..."
docker stop "$CONTAINER_NAME" 2>/dev/null && echo "✓ Container stopped" || echo "✓ Container not running"

# Remove the container with volumes
echo "Removing container..."
docker rm -fv "$CONTAINER_NAME" 2>/dev/null && echo "✓ Container removed" || echo "✓ Container not found"

# Remove the image
echo "Removing image..."
docker rmi "$CONTAINER_NAME" 2>/dev/null && echo "✓ Image removed" || echo "✓ Image not found"

echo ""
echo "Container $CONTAINER_NAME has been removed successfully!"
