local MYara = {
    flags = {
        CALLBACK_MSG_RULE_MATCHING = 1,
        CALLBACK_CONTINUE = 0,
        SCAN_FLAGS_FAST_MODE = 1,
        CALLBACK_MSG_SCAN_FINISHED = 3
    },
    yara = nil,
    saved_rules = {},
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
    self.yara:unload_rules()
    self.yara:unload_compiler()
    self.yara:load_compiler()
end

function MYara:backup_save_rules()
    local stream <const> = self.Config:get("yaragate.rules.backup")
    self.Logging:info(string.format("Saving backup yara rules in {%s}", stream))
    self.yara:save_rules_file(stream)
end

function MYara:backup_recover_rules()
    local stream <const> = self.Config:get("yaragate.rules.backup")
    self.yara:load_rules_file(stream)
end

function MYara:load_rules_saved()
    for index, value in ipairs(self.saved_rules) do
        self.yara:set_rule_file(value.path, "", value.namespace)
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

return MYara
