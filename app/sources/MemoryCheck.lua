-- Class to detect if a new library segment appears in memory
local MemoryCheck = { previous_segments = {}, list_suspicious = {} }
MemoryCheck.__index = MemoryCheck

require("libinfinity")

local mem = Memory:new()

function MemoryCheck:new()
    return setmetatable({}, MemoryCheck)
end

function MemoryCheck:found_lib_suspicious()
    mem:update()

    -- First run: store current segments
    if next(self.previous_segments) == nil then
        for _, segment in ipairs(mem.segments) do
            self.previous_segments[segment.start] = segment
        end
        return false -- First check, no suspicion yet
    end

    for _, segment in ipairs(mem.segments) do
        local old_segment = self.previous_segments[segment.start]
        if old_segment then
            if old_segment.type ~= segment.type and
                old_segment.permission ~= segment.permission then
                    self.list_suspicious[segment.start] = segment
            end
        else
            self.list_suspicious[segment.start] = segment
        end
    end

    return next(self.list_suspicious) ~= nil
end

return MemoryCheck
