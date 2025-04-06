local Ui = { Server = nil, Config = nil, Logging = nil, }

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
    if (self.Config:get("yaragate.activate.ui")) then
        local file <close> = io.open("plugins/yaragate/ui/html/index.html", "r")
        local buffer = nil
        if (file) then
            buffer = file:read("*all")
        end
        self.Server:create_route("/ui", HTTPMethod.Get, function(req)
            if self.Config:get("yaragate.activate.ui") then
                local mustache = Mustache:new(buffer)
                return mustache:render()
            end
        end)
    end
end

return Ui
