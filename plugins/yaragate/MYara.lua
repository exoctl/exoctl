local MYara = {
    flags = {
        CALLBACK_MSG_RULE_MATCHING = 1,
        CALLBACK_CONTINUE = 0,
        SCAN_FLAGS_FAST_MODE = 1,
        CALLBACK_MSG_SCAN_FINISHED = 3
    },
    reset_time = nil,
    yara = nil,
    saved_rules = {},
    Config = nil,
    Logging = nil,
    is_life = nil,
}

function MYara:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function MYara:setup(config, logging)
    self.is_life = false
    self.Logging = logging
    self.Config = config
    self.reset_time = self.Config:get("yaragate.rules.destroy.server.tick_time")
    self.yara = Yara:new()
end

function MYara:load()
    self.yara:load_rules()
    self.is_life = true
end

function MYara:reload()
    self.is_life = false
    self.Logging:info("Reload yara ...")
    self.yara:unload_rules()
    self.yara:unload_compiler()
    self.yara:load_compiler()
end

function MYara:backup_save_rules()
    local stream <const> = self.Config:get("yaragate.rules.backup")
    self.Logging:info(string.format("Saving backup yara rules to {%s}", stream))
    self.yara:save_rules_file(stream)
end

function MYara:backup_recover_rules()
    local stream <const> = self.Config:get("yaragate.rules.backup")
    self.Logging:info(string.format("Loading backup yara rules {%s}", stream))
    self.yara:load_rules_file(stream)
    self.is_life = true
end

function MYara:load_rules_saved()
    for index, value in ipairs(self.saved_rules) do
        self.yara:set_rule_file(value.path, nil, value.namespace)
    end
end

function MYara:save_rule(rule, namespace)
    local path <const> = self.Config:get("yaragate.rules.path") .. _data.metadata.sha:gen_sha256_hash(rule) .. ".yar"
    self.Logging:info(string.format("Saving yara rule in {%s}", path))

    local rule_file <close> = io.open(path, "w")
    if (rule_file ~= nil) then
        rule_file:write(rule)
        table.insert(self.saved_rules, { path = path, namespace = namespace })
    end
end

function MYara:reset_rules()
    for index, value in ipairs(self.saved_rules) do
        self.Logging:info(string.format("Reseting the rule {%s}", value.path))
        os.remove(value.path)
    end
    self.saved_rules = {}

    self:reload()
    self:load()
end

return MYara
