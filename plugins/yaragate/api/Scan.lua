local Scan = { Server = nil, MYara = nil }

function Scan:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function Scan:setup(server, myara)
    self.Server = server
    self.MYara = myara
end

function Scan:load()
    self.Server:create_route("/api/scan", HTTPMethod.Post, function(req)
        local rules_match = Json:new()
        self.MYara.yara:scan_bytes(req.body, function(message, rules)
            if message == self.MYara.flags.CALLBACK_MSG_RULE_MATCHING then
                local rule = Json:new()
                rule:add("identifier", rules.identifier)
                rule:add("namespace", rules.ns.name)
                rule:add("num_atoms", rules.num_atoms)
                
                if _engine.version and _engine.version.code >= _engine.version:version(1, 1, 0) then
                    rules_match:add(rule)
                else
                    rules_match:add(rule.identifier, rule)
                end

                return self.MYara.flags.CALLBACK_CONTINUE
            elseif message == self.MYara.flags.CALLBACK_MSG_SCAN_FINISHED then
                self.Server.Logging:info(("Scan completed successfully for IP {%s}"):format(req.remote_ip_address))
            end

            return self.MYara.flags.CALLBACK_CONTINUE
        end, self.MYara.flags.SCAN_FLAGS_FAST_MODE)

        local json_response = Json:new()
        json_response:add("sha256", _data.metadata.sha:gen_sha256_hash(req.body))
        json_response:add("rules_match", rules_match)

        return Response.new(200, "application/json", json_response:to_string())
    end)
end

return Scan
