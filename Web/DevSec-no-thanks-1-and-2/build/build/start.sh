#!/bin/bash
# Start SSH service
service ssh start || echo "Failed to start SSH"

# Start Nginx
service nginx start || echo "Failed to start Nginx"

# Print status
echo "Container started successfully"

# Keep container running
tail -f /dev/null
