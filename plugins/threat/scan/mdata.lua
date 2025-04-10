local MData = {
    Config = nil,
    Logging = nil,
    Magic = nil,
    Sha = nil
}

function MData:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function MData:setup(config, logging)
    self.Logging = logging
    self.Config = config
    self.Magic = Magic:new()
    self.Sha = Magic:new()
end

function MData:extract(buff)
    self.Magic:load_mime(buff)

    return {
        mime = self.Magic.mime,
        sha256 = self.Sha:gen_sha256_hash(buff)
    }
end

return MData
