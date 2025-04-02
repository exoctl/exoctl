local Ui = { Server = nil, Config = nil, Logging = nil }

function Ui:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function Ui:setup(config, logging, server)
    self.Server = server
    self.Config = config
    self.Logging = logging
end

function Ui:load()
    self.Server:create_route("/ui", HTTPMethod.Get, function(req)
        if self.Config:get("yaragate.activate.ui") then
            local file <close> = io.open("plugins/yaragate/ui/html/index.html", "r")
            if (file) then
                local ctx = Wvalue:new()
                ctx["server"] = "http://" ..
                    _engine.configuration:get("server.bindaddr") ..
                    ':' .. _engine.configuration:get("server.port") .. self.Config:get("yaragate.gateway.prefix")
                local mustache = Mustache:new(file:read("*all"))
                return mustache:render(ctx)
            end
        end
    end)
end

return Ui
