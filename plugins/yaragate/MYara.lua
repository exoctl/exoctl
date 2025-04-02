local MYara = {
    flags = {
        CALLBACK_MSG_RULE_MATCHING = 1,
        CALLBACK_CONTINUE = 0,
        SCAN_FLAGS_FAST_MODE = 1,
        CALLBACK_MSG_SCAN_FINISHED = 3
    },
    yara = nil,
    Config = nil,
    Logging = nil
}

function MYara:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function MYara:setup(config, logging)
    self.Logging = logging
    self.Config = config
    self.yara = Yara:new()
end

function MYara:load()
    self.yara:load_rules()
end

function MYara:reload()
    self.Logging:info("Reload yara ...")
    --self.yara:unload_rules()
    self.yara:unload_compiler()
    self.yara:load_compiler()
end

function MYara:save_rules_file()
    local stream <const> = self.Config:get("yaragate.rules.save_stream")
    self.Logging:info(string.format("Saving yara rules in {%s}", stream))
    self.yara:save_rules_file(self.Config:get("yaragate.rules.save_stream"))
end

function MYara:load_rules_file()
    local stream <const> = self.Config:get("yaragate.rules.save_stream")
    self.Logging:info(string.format("Loading yara rules in {%s}", stream))
    self.yara:load_rules_file(self.Config:get("yaragate.rules.save_stream"))
end

return MYara
