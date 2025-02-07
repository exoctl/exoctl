local yara_instance = Yara.new()

yara_instance:load_rules(function ()
    yara_instance:load_rules_folder("./rules/")
end)


local http_method = HTTPMethod.new()

Web.new(_server, "/engine/status", function (req)
    if(req.method == http_method.Get) then
        return Response.new(200, "The best engine for analysis malware")
    else
        return Response.new(200, "Outhers method")
    end
    
end, http_method.Post, http_method.Delete, http_method.Get)

local sha = Sha.new()
_logging:info("gen_sha256_hash(best_engine) = " .. sha:gen_sha256_hash("best_engine"))
_logging:info("Rules loaded: " .. tostring(yara_instance.rules_loaded_count))

yara_instance:scan_fast_bytes("some_binary_data", function(data)
    if data.match == 1 then
        _logging:warn("Match encontrado:", data.rule, "namespace:", data.ns)
    else
        _logging:info("Nenhum match.")
    end
end)