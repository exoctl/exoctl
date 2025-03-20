local engine <const> = _engine
local yara <const> = Yara:new()
local config <const> = Configuration:new()
local logging <const> = Logging:new()

config:setup("plugins/feedyara.conf")
config:load()

logging:setup(config)
logging:load()

local rules <const> = config:get("feedyara.rules")
yara:load_rules(function()
    yara:load_rules_folder(rules)
end)

local tick_time = config:get("feedyara.tick_time")
engine.server:tick(tick_time * 1000, function()

end)

-- comunation using gateway
local gateway_prefix <const> = config:get("feedyara.gateway.prefix")
Web.new(engine.server, gateway_prefix .. "/get/rules", function(req)
    local json = Json:new()
    yara:rules_foreach(function(rule)
        yara:metas_foreach(rule, function(meta)
            local value = function()
                if (meta.type ~= 2) then
                    return meta.integer
                else
                    return meta.string
                end
            end
        end)
    end)

    return Response.new(200, "application/json", json:to_string())
end)
