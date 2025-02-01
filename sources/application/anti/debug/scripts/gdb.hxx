#pragma once

inline const char *ANTI_DEBUG_PTRACE =
    "-- Detect if the process is being traced via ptrace\n"
    "local function is_ptrace_attached()\n"
    "    local f = io.open(\"/proc/self/status\", \"r\")\n"
    "    if not f then return false end\n"
    "    for line in f:lines() do\n"
    "        local tracer_pid = line:match(\"TracerPid:%s+(%d+)\")\n"
    "        if tracer_pid and tonumber(tracer_pid) > 0 then\n"
    "            f:close()\n"
    "            os.exit(1) -- Exit immediately if detected\n"
    "        end\n"
    "    end\n"
    "    f:close()\n"
    "end\n"
    "local clock = os.clock\n"
    "function sleep(n)\n"
    "    local t0 = clock()\n"
    "    while clock() - t0 <= n do end\n"
    "end\n"
    "sleep(20)\n"
    "is_ptrace_attached()\n";
    

inline const char *ANTI_DEBUG_BREAKPOINTS =
    "-- Detect if breakpoints are active\n"
    "local function has_breakpoints()\n"
    "    local dbg = require('debug')\n"
    "    local info = dbg.getinfo(1, 'S')\n"
    "    if info and info.what == 'C' then\n"
    "        os.exit(1) -- Exit immediately if detected\n"
    "    end\n"
    "end\n"
    "local clock = os.clock\n"
    "function sleep(n)\n"
    "    local t0 = clock()\n"
    "    while clock() - t0 <= n do end\n"
    "end\n"
    "sleep(20) -- Sleep to reduce CPU usage\n"
    "has_breakpoints()\n";

inline const char *ANTI_DEBUG_HOOK =
    "-- Detect if a debug hook is active\n"
    "local function is_debug_hook_active()\n"
    "    local dbg = require('debug')\n"
    "    if dbg.gethook() ~= nil then\n"
    "        os.exit(1) -- Exit immediately if detected\n"
    "    end\n"
    "end\n"
    "local clock = os.clock\n"
    "function sleep(n)\n"
    "    local t0 = clock()\n"
    "    while clock() - t0 <= n do end\n"
    "end\n"
    "sleep(20) -- Sleep to reduce CPU usage\n"
    "is_debug_hook_active()\n";

