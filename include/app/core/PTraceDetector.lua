-- Class to detect if the process is being traced via ptrace
local PTraceDetector = {}
PTraceDetector.__index = PTraceDetector

function PTraceDetector:new()
    return setmetatable({}, PTraceDetector)
end

function PTraceDetector:is_traced()
    local f = io.open("/proc/self/status", "r")
    if not f then
        return false
    end
    for line in f:lines() do
        local tracer_pid = line:match("TracerPid:%s+(%d+)")
        if tracer_pid and tonumber(tracer_pid) > 0 then
            f:close()
            return true
        end
    end
    f:close()
    return false
end

function PTraceDetector:is_gdb_environment_present()
    local env_file = io.open("/proc/self/environ", "r")
    if not env_file then
        return false
    end

    local environ_data = env_file:read("*a")
    env_file:close()

    return environ_data:lower():match("gdb") ~= nil
end

return PTraceDetector
