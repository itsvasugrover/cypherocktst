#!/bin/bash

# Clean script to remove keys from client and server directories

echo "Cleaning keys..."

# Remove client keys if directory exists
if [ -d "client/keys" ]; then
    rm -rf client/keys
    echo "Removed client/keys"
fi

# Remove server keys if directory exists
if [ -d "server/keys" ]; then
    rm -rf server/keys
    echo "Removed server/keys"
fi

echo "Clean complete."