local GetRules = { Server = nil, MYara = nil }

function GetRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function GetRules:setup(server, myara)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(myara) == "table", "Invalid MYara instance")

    self.Server = server
    self.MYara = myara
end

function GetRules:load()
    self.Server:create_route("/api/get/rules", HTTPMethod.Get, function(req)
        local rules_json = Json:new()

        if not self.MYara or not self.MYara.is_life then
            return self:create_error_response(500, "Yara engine is not initialized")
        end

        self.MYara.yara:rules_foreach(function(rules)
            if rules then
                local meta = Json:new()

                self.MYara.yara:metas_foreach(rules, function(metas)
                    if metas then
                        local value = (metas.type ~= 2) and metas.integer or metas.string
                        meta:add(metas.identifier, value)
                    end
                end)

                local rule = Json:new()
                rule:add("identifier", rules.identifier or "unknown")
                rule:add("namespace", (rules.ns and rules.ns.name) or "unknown")
                rule:add("num_atoms", rules.num_atoms or 0)
                rule:add("meta", meta)

                rules_json:add(rules.identifier or "unknown", rule)
            end
        end)

        local response = Json:new()
        response:add("rules", rules_json)

        return Response:new(200, "application/json", response:to_string())
    end)
end

function GetRules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:to_string())
end

return GetRules
