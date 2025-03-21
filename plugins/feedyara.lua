local engine <const> = _engine
local scan_yara <const> = Yara:new()
local config <const> = Configuration:new()
local logging <const> = Logging:new()
local message_yara <const> = { CALLBACK_MSG_RULE_MATCHING = 1, CALLBACK_CONTINUE = 0, SCAN_FLAGS_FAST_MODE = 1, CALLBACK_MSG_SCAN_FINISHED = 3 }

config:setup("plugins/feedyara.conf")
config:load()

logging:setup(config)
logging:load()

local rules_folder <const> = config:get("feedyara.rules.path")

local function load_rules()
    scan_yara:load_rules(function()
        scan_yara:load_rules_folder(rules_folder)
    end)
end

-- load initial rules
load_rules()

-- create a tick on the server to check for new rules
local tick_time = config:get("feedyara.server.tick_time")
engine.server:tick(tick_time * 1000, function()
    local rules_save_stream = config:get("feedyara.rules.save_stream")

    scan_yara:save_rules_file(rules_save_stream)
    scan_yara:unload_rules()
    scan_yara:unload_compiler()
    scan_yara:load_compiler()
    --scan_yara:load_rules_file(rules_save_stream)
    scan_yara:load_rules_folder(rules_folder)

    scan_yara:load_rules()
end)

-- Communication using gateway
local gateway_prefix <const> = config:get("feedyara.gateway.prefix")

Web.new(engine.server, gateway_prefix .. "/get/rules", function(req)
    logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}"):format(
        req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor, tostring(req.keep_alive)
    ))

    local rules_json = Json:new()

    scan_yara:rules_foreach(function(rules)
        local meta = Json:new()

        scan_yara:metas_foreach(rules, function(metas)
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
end, HTTPMethod.Get)


scan_yara:scan_bytes("aaa", function(message, rule)
        
    if (message == message_yara.CALLBACK_MSG_RULE_MATCHING) then
        _engine.logging:info("Rule identifier" .. rule.identifier)
        _engine.logging:info("Rule ns name" .. rule.ns.name)
    elseif (message == 3) then
        logging:info(("The scan was completed successfully for ip {%s} "):format(1))
    end

    return message_yara.CALLBACK_CONTINUE
end, message_yara.SCAN_FLAGS_FAST_MODE)


Web.new(engine.server, gateway_prefix .. "/scan", function(req)
    logging:info(("Request received: method={%s}, url={%s}, remote_ip={%s}, http_version={%d.%d}, keep_alive={%s}"):format(
        req.method, req.url, req.remote_ip_address, req.http_ver_major, req.http_ver_minor, tostring(req.keep_alive)
    ))

    scan_yara:scan_bytes(req.body, function(message, rule)
        
        if (message == message_yara.CALLBACK_MSG_RULE_MATCHING) then
            _engine.logging:info("Rule identifier" .. rule.identifier)
            _engine.logging:info("Rule ns name" .. rule.ns.name)
        elseif (message == 3) then
            logging:info(("The scan was completed successfully for ip {%s} "):format(req.remote_ip_address))
        end

        return message_yara.CALLBACK_CONTINUE
    end, message_yara.SCAN_FLAGS_FAST_MODE)

    local json_response = Json:new()
    json_response:add("scan", "")

    return Response.new(200, "application/json", json_response:to_string())
end, HTTPMethod.Post)
