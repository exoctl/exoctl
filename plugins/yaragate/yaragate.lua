-- ========================
-- Initialization and Configuration
-- ========================

local engine <const> = _engine
local yara <const> = Yara:new()
local config <const> = Configuration:new()
local logging <const> = Logging:new()

local flags_yara <const> = {
    CALLBACK_MSG_RULE_MATCHING = 1,
    CALLBACK_CONTINUE = 0,
    SCAN_FLAGS_FAST_MODE = 1,
    CALLBACK_MSG_SCAN_FINISHED = 3
}

-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("plugins/yaragate/yaragate.conf")
config:load()

logging:setup(config)
logging:load()

local rules_folder <const> = config:get("yaragate.rules.path")
local rules_save_stream = config:get("yaragate.rules.save_stream")
local tick_time = config:get("yaragate.server.tick_time")
local gateway_prefix <const> = config:get("yaragate.gateway.prefix")

-- ========================
-- Helper Functions
-- ========================

-- Logs request details
local function log_request(req)
    logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}")
        :format(req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor,
            tostring(req.keep_alive))
    )
end

-- Load Yara rules
local function load_rules()
    yara:load_rules(function()
        yara:load_rules_folder(rules_folder)
    end)
end

-- Reload Yara rules and compiler
local function reload_yara()
    yara:unload_rules()
    yara:unload_compiler()
    yara:load_compiler()
end

-- ========================
-- Initial Rule Load
-- ========================
load_rules()
yara:save_rules_file(rules_save_stream)


local ftick <const> = function()
    logging:debug(("Maintaining rules, loading rules from folder '{%s}' ..."):format(rules_folder))

    reload_yara()
    load_rules()
    yara:load_rules_file(rules_save_stream)
end

-- Set up periodic tick
engine.server:tick(tick_time * 1000, ftick)

-- ========================
-- API Endpoints
-- ========================

-- Function to create routes dynamically
local function create_route(endpoint, method, handler)
    Web.new(engine.server, gateway_prefix .. endpoint, function(req)
        log_request(req)
        return handler(req)
    end, method)
end

-- ---------------
-- Route: Get Yara Rules
-- ---------------

create_route("/get/rules", HTTPMethod.Get, function(req)
    local rules_json = Json:new()

    yara:rules_foreach(function(rules)
        local meta = Json:new()

        yara:metas_foreach(rules, function(metas)
            local value = (metas.type ~= 2) and metas.integer or metas.string
            meta:add(metas.identifier, value)
        end)

        local rule = Json:new()
        rule:add("identifier", rules.identifier)
        rule:add("namespace", rules.ns.name)
        rule:add("num_atoms", rules.num_atoms)
        rule:add("meta", meta)

        rules_json:add(rules.identifier, rule)
    end)

    local json_response = Json:new()
    json_response:add("rules", rules_json)

    return Response.new(200, "application/json", json_response:to_string())
end)

-- ---------------
-- Route: Perform Yara Scan
-- ---------------

create_route("/scan", HTTPMethod.Post, function(req)
    local rules_match = Json:new()

    yara:scan_bytes(req.body, function(message, rules)
        if message == flags_yara.CALLBACK_MSG_RULE_MATCHING then
            local rule = Json:new()
            rule:add("identifier", rules.identifier)
            rule:add("namespace", rules.ns.name)
            rule:add("num_atoms", rules.num_atoms)
            rules_match:add(rules.identifier, rule)

            return flags_yara.CALLBACK_CONTINUE
        elseif message == flags_yara.CALLBACK_MSG_SCAN_FINISHED then
            logging:info(("Scan completed successfully for IP {%s}"):format(req.remote_ip_address))
        end

        return flags_yara.CALLBACK_CONTINUE
    end, flags_yara.SCAN_FLAGS_FAST_MODE)

    local json_response = Json:new()
    json_response:add("sha256", _data.metadata.sha:gen_sha256_hash(req.body))
    json_response:add("rules_match", rules_match)

    return Response.new(200, "application/json", json_response:to_string())
end)

-- ---------------
-- Route: Force Execution of Yara Tick
-- ---------------

create_route("/force/tick/yara", HTTPMethod.Post, function(req)
    ftick()
end)

-- ---------------
-- Route: Load New Yara Rule
-- ---------------

create_route("/load/yara/rule", HTTPMethod.Post, function(req)
    local json = Json:new()
    json:from_string(req.body)

    local rule = json:get("rule")
    local namespace = json:get("namespace")

    if not rule or not namespace then
        local message = Json:new()
        message:add("message", "Missing required fields: 'rule' and 'namespace' are required.")

        return Response.new(400, "application/json", message:to_string())
    end

    -- Reload Yara with new rule
    reload_yara()
    local compiled_rule = true

    yara:load_rules(function()
        if (yara:set_rule_buff(rule, namespace) ~= 0) then
            reload_yara()
            compiled_rule = false
        end

        load_rules()
    end)

    if compiled_rule then
        print(yara:save_rules_file(rules_save_stream)) -- Backup rules
        local message = Json:new()
        message:add("message", "Rule compiled successfully")

        return Response.new(200, "application/json", message:to_string())
    end

    local message = Json:new()
    message:add("message", "The rule was not compiled successfully, check for possible syntax errors")

    return Response.new(400, "application/json", message:to_string())
end)