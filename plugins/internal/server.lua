-- Classe Server
Server = {}
Server.__index = Server

function Server:new()
    local instance = setmetatable({}, Server)
    return instance
end

function Server:bindaddr()
    return server.bindaddr()
end

function Server:port()
    return server.port()
end