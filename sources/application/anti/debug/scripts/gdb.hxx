#ifdef PROTECT_ANTI_DEBUG

#pragma once

inline const char *ANTI_DEBUG_PTRACE =
    "-- Detect if the process is being traced via ptrace using coroutine\n"
    "local function is_ptrace_attached()\n"
    "    return coroutine.create(function()\n"
    "        while true do\n"
    "            local f = io.open(\"/proc/self/status\", \"r\")\n"
    "            if not f then\n"
    "                coroutine.yield() -- Se o arquivo não puder ser aberto, "
    "espere até o processo acabar\n"
    "                return\n"
    "            end\n"
    "            for line in f:lines() do\n"
    "                local tracer_pid = line:match(\"TracerPid:%s+(%d+)\")\n"
    "                if tracer_pid and tonumber(tracer_pid) > 0 then\n"
    "                    f:close()\n"
    "                    os.exit(1) -- Exit immediately if detected\n"
    "                end\n"
    "            end\n"
    "            f:close()\n"
    "            coroutine.yield() -- Yield para reduzir uso da CPU\n"
    "        end\n"
    "    end)\n"
    "end\n"
    "local co = is_ptrace_attached()\n"
    "while true do\n"
    "    coroutine.resume(co)\n"
    "end\n";

inline const char *ANTI_DEBUG_BREAKPOINTS =
    "-- Detect if breakpoints are active using coroutine\n"
    "local function has_breakpoints()\n"
    "    return coroutine.create(function()\n"
    "        while true do\n"
    "            local dbg = require('debug')\n"
    "            local info = dbg.getinfo(1, 'S')\n"
    "            if info and info.what == 'C' then\n"
    "                os.exit(1) -- Exit immediately if detected\n"
    "            end\n"
    "            coroutine.yield() -- Yield for check again\n"
    "        end\n"
    "    end)\n"
    "end\n"
    "local co = has_breakpoints()\n"
    "while true do\n"
    "    coroutine.resume(co)\n"
    "end\n";

inline const char *ANTI_DEBUG_HOOK =
    "-- Detect if a debug hook is active using coroutine\n"
    "local function is_debug_hook_active()\n"
    "    return coroutine.create(function()\n"
    "        while true do\n"
    "            local dbg = require('debug')\n"
    "            if dbg.gethook() ~= nil then\n"
    "                os.exit(1) -- Exit immediately if detected\n"
    "            end\n"
    "            coroutine.yield() -- Yield for check again\n"
    "        end\n"
    "    end)\n"
    "end\n"
    "local co = is_debug_hook_active()\n"
    "while true do\n"
    "    coroutine.resume(co)\n"
    "end\n";

#endif