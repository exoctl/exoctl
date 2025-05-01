local Utils = {}
Utils.__index = Utils

function Utils:new()
    return setmetatable({}, Utils)
end

-- I do not recommend using this sleep to reduce CPU consumption in a thread
function Utils:sleep(n)
    local t0 = os.clock()
    while os.clock() - t0 <= n do end
end

return Utils
