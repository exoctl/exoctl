local GetRules = { Server = nil, MYara = nil }

function GetRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function GetRules:setup(server, myara)
    self.Server = server
    self.MYara = myara
end

function GetRules:load()
    self.Server:create_route("/api/get/rules", HTTPMethod.Get, function(req)
        local rules_json = Json:new()

        self.MYara.yara:rules_foreach(function(rules)
            if (rules) then
                local meta = Json:new()

                self.MYara.yara:metas_foreach(rules, function(metas)
                    local value = (metas.type ~= 2) and metas.integer or metas.string
                    meta:add(metas.identifier, value)
                end)

                local rule = Json:new()
                rule:add("identifier", rules.identifier)
                rule:add("namespace", rules.ns.name)
                rule:add("num_atoms", rules.num_atoms)
                rule:add("meta", meta)

                rules_json:add(rules.identifier, rule)
            end
        end)

        local response = Json:new()
        response:add("rules", rules_json)

        return Response.new(200, "application/json", response:to_string())
    end)
end

return GetRules
