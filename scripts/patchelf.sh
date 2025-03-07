#!/bin/bash

# Check if the user provided the library path as an argument
if [[ -z "$1" ]]; then
    echo "Usage: $0 <path_to_library>"
    exit 1
fi

# Get the absolute path of the original library
original_lib=$(realpath "$1")

# Define the directory where the libraries will be copied
new_lib_path=$(dirname "$original_lib")

# File where all dependencies will be listed
deps_file="libs.so.list"
rm -f "$deps_file"
touch "$deps_file"

# Set a limit for open files to avoid "Too many open files"
ulimit -n 4096

# Hashmap to prevent processing the same library multiple times
declare -A checked_libs

# Log function for consistent output
log() {
    echo "[INFO] $1"
}

# Error log function
log_error() {
    echo "[ERROR] $1"
}

# Function to collect dependencies recursively
function collect_dependencies() {
    local lib="$1"

    # If the library has already been processed, return
    if [[ -n "${checked_libs[$lib]}" ]]; then
        return
    fi
    checked_libs["$lib"]=1  # Mark the library as processed

    # Get all dependencies, ignoring "linux-vdso.so.1"
    ldd "$lib" 2>/dev/null | awk '{if ($3 ~ /^\//) print $3; else if ($1 ~ /^\//) print $1}' | grep -v "linux-vdso.so.1" >> "$deps_file"

    # Remove duplicates
    sort -u -o "$deps_file" "$deps_file"

    # Process each dependency recursively
    while IFS= read -r dep_lib; do
        collect_dependencies "$dep_lib"
    done < "$deps_file"
}

# First call to collect dependencies from the original library
log "Collecting dependencies for the original library: $original_lib"
collect_dependencies "$original_lib"

# Copy all listed libraries to the local directory and adjust permissions
log "Copying libraries to the local directory: $new_lib_path"
while IFS= read -r lib_path; do
    lib_name=$(basename "$lib_path")
    new_lib="$new_lib_path/$lib_name"

    # If the library hasn't been copied yet, copy it to the local directory
    if [[ ! -f "$new_lib" ]]; then
        log "Copying $lib_name to $new_lib"
        cp "$lib_path" "$new_lib"
        chmod +x "$new_lib"  # Ensure execute permissions
    fi
done < "$deps_file"

# Now patch the dependencies, including the original library
log "Patching dependencies and adjusting paths"
while IFS= read -r lib_path; do
    lib_name=$(basename "$lib_path")
    new_lib="$new_lib_path/$lib_name"

    # Patch ELF to use the local version (relative path)
    log "Patching $lib_name to use relative path in $new_lib"
    patchelf --replace-needed "$lib_name" "./$lib_name" "$new_lib"

    # After patching, collect the dependencies of the modified library
    collect_dependencies "$new_lib"

done < "$deps_file"

# Now fix the internal dependencies (all modified libraries)
log "Fixing internal dependencies"
while IFS= read -r lib_path; do
    lib_name=$(basename "$lib_path")
    new_lib="$new_lib_path/$lib_name"

    while IFS= read -r inner_dep; do
        inner_name=$(basename "$inner_dep")
        inner_new_lib="$new_lib_path/$inner_name"

        log "Fixing internal dependency: $inner_name -> ./$inner_name in $new_lib"
        # Fix internal dependencies to use relative paths
        patchelf --replace-needed "$inner_name" "./$inner_name" "$new_lib"

    done < "$deps_file"

done < "$deps_file"

# Adjust the original library to look for libraries in the current directory
log "Adjusting the original library $original_lib to search for libraries in the current directory"

# Patch ELF for the original library
log "Setting rpath to \$ORIGIN in $original_lib"
patchelf --set-rpath "\$ORIGIN" "$original_lib"

# Patch the original library to use relative paths for its dependencies
while IFS= read -r lib_path; do
    lib_name=$(basename "$lib_path")
    new_lib="$new_lib_path/$lib_name"

    log "Adjusting dependency $lib_name to local directory in $original_lib"
    # Replace dependencies in the original library to search in the local directory
    patchelf --replace-needed "$lib_name" "./$lib_name" "$original_lib"

done < "$deps_file"

log "All dependencies have been copied to the local directory, and the original library has been adjusted to search for libraries locally."
