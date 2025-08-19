local yara_gate = {
    reset_time = nil,
    yara = nil,
    saved_rules = {},
    config = nil,
    logging = nil,
    is_life = nil,
}

function yara_gate:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function yara_gate:setup(config, logging)
    self.is_life = false
    self.logging = logging
    self.config = config
    self.yara = _bridge.analysis.analysis.threats["yara"]
end

function yara_gate:load()
    self.is_life = true
end

function yara_gate:reload()
    self.is_life = false
    self.logging:info("Reload yara ...")
    self.yara:unload_rules()
    self.yara:unload_compiler()
    self.yara:load_compiler()
end

function yara_gate:backup_save_rules()
    local stream <const> = self.config:get("yara.rules.backup")
    self.logging:info(string.format("Saving backup yara rules to {%s}", stream))
    self.yara:save_rules_file(stream)
end

function yara_gate:backup_recover_rules()
    local stream <const> = self.config:get("yara.rules.backup")
    self.logging:info(string.format("Loading backup yara rules {%s}", stream))
    self.yara:load_rules_file(stream)
    self.is_life = true
end

function yara_gate:load_rules_saved()
    for index, value in ipairs(self.saved_rules) do
        self.yara:set_rule_file(value.path, nil, value.namespace)
    end
end

function yara_gate:save_rule(rule, namespace)
    local path <const> = self.config:get("yara.rules.path") .. _data.metadata.sha:sha256(rule) .. ".yar"
    self.logging:info(string.format("Saving yara rule in {%s}", path))

    local rule_file <close> = io.open(path, "w")
    if (rule_file ~= nil) then
        rule_file:write(rule)
        table.insert(self.saved_rules, { path = path, namespace = namespace })
    end
end

function yara_gate:reset_rules()
    for index, value in ipairs(self.saved_rules) do
        self.logging:info(string.format("Reseting the rule {%s}", value.path))
        os.remove(value.path)
    end
    self.saved_rules = {}

    self:reload()
    self:load()
end

return yara_gate