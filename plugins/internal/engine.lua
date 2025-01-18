-- Classe Engine
Engine = {}
Engine.__index = Engine

function Engine:new()
    local instance = setmetatable({}, Engine)
    return instance
end

function Engine:is_running()
    return engine.is_running()
end