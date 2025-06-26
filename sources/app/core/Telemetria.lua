-- Class to telemetria get infos if detected anomalies
local Telemetria = {
    previous_segments = {},
    last_mem_check_time = os.time(),
    lasted_lib_dumped = {},
    list_suspicious = {}
}

Telemetria.__index = Telemetria

function Telemetria:new()
    return setmetatable({}, Telemetria)
end

local MemoryCheck = require("MemoryCheck")
local PTraceDetector = require("PTraceDetector")
Envvar = require("Envvar")

local Utils = require("Utils")

local ptrace = PTraceDetector:new()
local utils = Utils:new()
local memorycheck = MemoryCheck:new()


function Telemetria:check_tracing()
    if ptrace:is_traced() or ptrace:is_gdb_environment_present() then
        utils:sleep(3)
        os.exit(1)
    end
end

function Telemetria:check_mem()
    local current_time = os.time()

    if (current_time - self.last_mem_check_time) >= 10 then
        self.last_mem_check_time = current_time

        if memorycheck:found_lib_suspicious() then
            local suspicious_libs = {}

            for start_addr, lib in pairs(memorycheck.list_suspicious) do
                if self.lasted_lib_dumped[start_addr] == nil then
                    table.insert(suspicious_libs, lib.name)
                    self.lasted_lib_dumped[start_addr] = lib
                end
            end

            if #suspicious_libs > 0 then
                for _, lib_name in ipairs(suspicious_libs) do
                   -- nothing
                end
            end
        end
    end
end

return Telemetria
