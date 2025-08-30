#!/bin/bash

# Script to rename C++ private variables from m_<variable> to <variable>_ in .cxx and .hxx files
# Usage: ./rename_vars.sh /path/to/your/codebase
# Recursively processes all .cxx and .hxx files in the specified directory and its subdirectories
# Uses GNU sed to perform a global search-and-replace for identifiers starting with 'm_'
# followed by a valid variable name, converting them to variable name followed by '_'
# WARNING: This affects all matches, including potential false positives in comments or strings
# Always backup your codebase before running
# Assumes variable names after 'm_' start with a letter [a-zA-Z], adjust regex if needed


if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/directory"
    exit 1
fi

DIRECTORY="$1"

if [ ! -d "$DIRECTORY" ]; then
    echo "Error: Directory '$DIRECTORY' does not exist."
    exit 1
fi

# Find all .cxx and .hxx files recursively and apply sed replacement
find "$DIRECTORY" -type f \( -name "*.cxx" -o -name "*.hxx" \) -exec sed -i 's/\bm_\([a-zA-Z][a-zA-Z0-9_]*\)\b/\1_/g' {} +

echo "Renaming completed. Please review changes and compile/test your code."