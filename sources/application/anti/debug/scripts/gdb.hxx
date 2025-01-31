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
    "has_breakpoints()\n";

inline const char *ANTI_DEBUG_HOOK =
    "-- Detect if a debug hook is active\n"
    "local function is_debug_hook_active()\n"
    "    local dbg = require('debug')\n"
    "    if dbg.gethook() ~= nil then\n"
    "        os.exit(1) -- Exit immediately if detected\n"
    "    end\n"
    "end\n"
    "is_debug_hook_active()\n";

inline const char *ANTI_DEBUG_CHECK =
    "-- Check all anti-debugging techniques and exit silently if a debugger is "
    "detected\n"
    "local function anti_debug_check()\n"
    "    if is_ptrace_attached() or has_breakpoints() or "
    "is_debug_hook_active() then\n"
    "        os.exit(1)\n"
    "    end\n"
    "end\n"
    "anti_debug_check()\n";
