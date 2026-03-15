#!/bin/bash

# Define the directory where Maude is located
MAUDE_DIR="./tools/maude"

# Function to check if Maude is in the PATH
is_maude_in_path() {
    command -v maude >/dev/null 2>&1
}

# Check if Maude is in the PATH
if is_maude_in_path; then
    echo "Maude is already in the PATH."
else
    echo "Maude is not in the PATH. Adding it now..."
    
    # Add Maude directory to PATH
    export PATH="$MAUDE_DIR:$PATH"
    
    # Optional: Append to ~/.bashrc or ~/.zshrc for persistence
    if [ -f ~/.bashrc ]; then
        echo "export PATH=\"$MAUDE_DIR:\$PATH\"" >> ~/.bashrc
        echo "Maude directory added to ~/.bashrc"
    elif [ -f ~/.zshrc ]; then
        echo "export PATH=\"$MAUDE_DIR:\$PATH\"" >> ~/.zshrc
        echo "Maude directory added to ~/.zshrc"
    else
        echo "No bash or zsh configuration file found. Update your shell configuration manually for persistence."
    fi
fi
