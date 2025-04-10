local Scan = {
    MYara = require("plugins.threat.scan.myara"):new(),
    MData = require("plugins.threat.scan.mdata"):new(),
    Config = nil,
    Logging = nil
}

function Scan:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function Scan:setup(config, logging)
    self.Logging = logging
    self.Config = config
    self.MYara:setup(config, logging)
    self.MData:setup(config, logging)
end

function Scan:load()
    self.MYara:load()
end

return Scan
