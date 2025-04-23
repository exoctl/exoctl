#!/bin/bash

DEST_FOLDER="app/AppDir"
mkdir -p "$DEST_FOLDER"

luac5.4 -o App.lua app/sources/App.lua
luac5.4 -o MemoryCheck.lua app/sources/MemoryCheck.lua
luac5.4 -o PTraceDetector.lua app/sources/PTraceDetector.lua
luac5.4 -o Telemetria.lua app/sources/Telemetria.lua
luac5.4 -o Utils.lua app/sources/Utils.lua
luac5.4 -o Version.lua app/sources/Version.lua
luac5.4 -o Envvar.lua app/sources/Envvar.lua

mv *.lua "$DEST_FOLDER"

echo "Compiled files in '$DEST_FOLDER/'"