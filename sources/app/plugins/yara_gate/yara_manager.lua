local yara_gate = {
    reset_time = nil,
    yara = nil,
    config = nil,
    logging = nil,
    is_life = nil,
    rules_backup = nil,
    rules_path = nil
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
    self.yara = _bridge.analysis.analysis["yara"]
    self.rules_path = _bridge.analysis.analysis.yara_rules_path
    self.rules_backup = self.config:get("yara.rules.backup")
end

function yara_gate:load()
    self.is_life = true
    self.yara:load_rules()
end

function yara_gate:reload()
    self.is_life = false
    self.logging:info("Reload yara ...")
    self.yara:unload_rules()
    self.yara:unload_compiler()
    self.yara:load_compiler()
end

function yara_gate:backup_save_rules()
    self.logging:info(string.format("Saving backup yara rules to {%s}", self.rules_backup))
    self.yara:save_rules_file(self.rules_backup)
end

function yara_gate:backup_recover_rules()
    self.logging:info(string.format("Loading backup yara rules {%s}", self.rules_backup))
    self.yara:load_rules_file(self.rules_backup)
    self.is_life = true
end

function yara_gate:save_rule(rule, namespace)
    _engine.filesystem:create_directories(self.rules_path .. "/" .. namespace, false)
    local path <const> = string.format("%s/%s/%s.yar", self.rules_path, namespace,
        _bridge.analysis.analysis["sha"]:sha256(rule))
    self.logging:info(string.format("Saving yara rule in {%s}", path))

    local rule_file <close> = io.open(path, "w")
    if (rule_file ~= nil) then
        rule_file:write(rule)
    end
end

return yara_gate
