local MCPServer <const>  = {
    config = nil,
    logging = nil,
    server = Server:new()
}

MCPServer.__index = MCPServer

function MCPServer:new()
    return setmetatable({}, MCPServer)
end

function MCPServer:setup(config, logging)
    self.config = config
    self.logging = logging

    self.server:setup(self.config, self.logging)
end

function MCPServer:run()
    self.server:run_async()
end

return MCPServer