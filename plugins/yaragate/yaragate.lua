-- ========================
-- Initialization and Configuration
-- ========================

local config <const> = Configuration:new()
local logging <const> = Logging:new()
local server <const> = require("plugins.yaragate.Server")
local api <const> = {
    get_rules = require("plugins.yaragate.api.get_rules"),
    scan = require("plugins.yaragate.api.scan"),
    load_rule = require("plugins.yaragate.api.load_rule")
}
local yara <const> = require("plugins.yaragate.MYara")
local ui <const> = require("plugins.yaragate.ui.ui")
-- ========================
-- Setup and Load Configuration
-- ========================

config:setup("plugins/yaragate/yaragate.conf")
config:load()

logging:setup(config)
logging:load()

yara:setup(config, logging)
yara:load()

server:setup(config, logging)

api.get_rules:setup(server, yara)
api.get_rules:load()

api.scan:setup(server, yara)
api.scan:load()

api.load_rule:setup(server, yara)
api.load_rule:load()

-- UI
ui:setup(config, logging, server)
ui:load()


-- ========================
-- API Endpoints
-- ========================

-- -- Function to create routes dynamically
-- local function create_route(endpoint, method, handler)
--     Web.new(engine.server, gateway_prefix .. endpoint, function(req)
--         log_request(req)
--         return handler(req)
--     end, method)
-- end

-- -- ---------------
-- -- Route: Get Yara Rules
-- -- ---------------

-- create_route("/api/get/rules", HTTPMethod.Get, function(req)
--     local rules_json = Json:new()

--     yara:rules_foreach(function(rules)
--         local meta = Json:new()

--         yara:metas_foreach(rules, function(metas)
--             local value = (metas.type ~= 2) and metas.integer or metas.string
--             meta:add(metas.identifier, value)
--         end)

--         local rule = Json:new()
--         rule:add("identifier", rules.identifier)
--         rule:add("namespace", rules.ns.name)
--         rule:add("num_atoms", rules.num_atoms)
--         rule:add("meta", meta)

--         rules_json:add(rules.identifier, rule)
--     end)

--     local json_response = Json:new()
--     json_response:add("rules", rules_json)

--     return Response.new(200, "application/json", json_response:to_string())
-- end)

-- -- ---------------
-- -- Route: Perform Yara Scan
-- -- ---------------

-- create_route("/api/scan", HTTPMethod.Post, function(req)
--     local rules_match = Json:new()
--     yara:scan_bytes(req.body, function(message, rules)
--         if message == flags_yara.CALLBACK_MSG_RULE_MATCHING then
--             local rule = Json:new()
--             rule:add("identifier", rules.identifier)
--             rule:add("namespace", rules.ns.name)
--             rule:add("num_atoms", rules.num_atoms)
--             if engine.version and engine.version.code >= engine.version:version(1, 1, 0) then
--                 rules_match:add(rule)
--             else
--                 rules_match:add(rule.identifier, rule)
--             end

--             return flags_yara.CALLBACK_CONTINUE
--         elseif message == flags_yara.CALLBACK_MSG_SCAN_FINISHED then
--             logging:info(("Scan completed successfully for IP {%s}"):format(req.remote_ip_address))
--         end

--         return flags_yara.CALLBACK_CONTINUE
--     end, flags_yara.SCAN_FLAGS_FAST_MODE)

--     local json_response = Json:new()
--     json_response:add("sha256", _data.metadata.sha:gen_sha256_hash(req.body))
--     json_response:add("rules_match", rules_match)

--     return Response.new(200, "application/json", json_response:to_string())
-- end)

-- -- ---------------
-- -- Route: Load New Yara Rule
-- -- ---------------

-- create_route("/api/load/yara/rule", HTTPMethod.Post, function(req)
--     local json = Json:new()
--     json:from_string(req.body)

--     local rule = json:get("rule")
--     local namespace = json:get("namespace")

--     if not rule or not namespace then
--         local message = Json:new()
--         message:add("message", "Missing required fields: 'rule' and 'namespace' are required.")

--         return Response.new(400, "application/json", message:to_string())
--     end

--     -- Reload Yara with new rule
--     reload_yara()
--     local compiled_rule = true

--     yara:load_rules(function()
--         if (yara:set_rule_buff(rule, namespace) ~= 0) then
--             reload_yara()
--             compiled_rule = false
--         end

--         load_rules()
--     end)

--     local message = Json:new()

--     if compiled_rule then
--         yara:save_rules_file(rules_save_stream) -- Backup rules
--         message:add("message", "Rule compiled successfully")

--         return Response.new(200, "application/json", message:to_string())
--     end

--     message:add("message", "The rule was not compiled successfully, check for possible syntax errors")

--     return Response.new(400, "application/json", message:to_string())
-- end)

-- if engine.version and engine.version.code >= engine.version:version(1, 1, 0) then

--     if config:get("yaragate.activate.ui") then
--         create_route("/ui", HTTPMethod.Get, function(req)
--             local file <close> = io.open("plugins/yaragate/ui/index.html", "r")
--             if (file) then
--                 local ctx = Wvalue:new()
--                 ctx["server"] = "http://" ..
--                 engine.configuration:get("server.bindaddr") ..
--                 ':' .. engine.configuration:get("server.port") .. gateway_prefix
--                 local mustache = Mustache:new(file:read("*all"))
--                 return mustache:render(ctx)
--             end
--         end)
--     end


--     create_route("/api/disable/yara/rule", HTTPMethod.Post, function(req)
--         local json = Json:new()
--         json:from_string(req.body)

--         local rule = json:get("rule")

--         if not rule then
--             local message = Json:new()
--             message:add("message", "Missing required fields: 'rule' are required.")

--             return Response.new(400, "application/json", message:to_string())
--         end

--         local disabled = false

--         yara:rules_foreach(function(rules)
--             if (rules.identifier == rule) then
--                 disabled = true
--                 yara:rule_disable(rules)
--             end
--         end)

--         local message = Json:new()

--         if disabled then
--             message:add("message", "Rule was disabled")
--             return Response.new(200, "application/json", message:to_string())
--         end

--         message:add("message", "The rule was not found")

--         return Response.new(400, "application/json", message:to_string())
--     end)

--     create_route("/api/enable/yara/rule", HTTPMethod.Post, function(req)
--         local json = Json:new()
--         json:from_string(req.body)

--         local rule = json:get("rule")

--         if not rule then
--             local message = Json:new()
--             message:add("message", "Missing required fields: 'rule' are required.")

--             return Response.new(400, "application/json", message:to_string())
--         end

--         local disabled = false

--         yara:rules_foreach(function(rules)
--             if (rules.identifier == rule) then
--                 disabled = true
--                 yara:rule_enable(rules)
--             end
--         end)

--         local message = Json:new()

--         if disabled then
--             message:add("message", "Rule was enabled")
--             return Response.new(200, "application/json", message:to_string())
--         end

--         message:add("message", "The rule was not found")

--         return Response.new(400, "application/json", message:to_string())
--     end)
-- end
