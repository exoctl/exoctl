local yara_instance = Yara.new()

yara_instance:load_rules(function ()
    yara_instance:load_rules_folder("./rules/")
end)

local sha = Sha.new()

_yara:scan_fast_bytes("some_binary_data", function(status, rule, ns)
    if status == 1 then
        _logging:warn("Match encontrado:", rule, "namespace:", ns)
    else
        _logging:info("Nenhum match.")
    end
end)

Web.new(_server, "/engine/status", function (req, args)
    print(req.raw_url)
    print(req.body)
    print(req.method)
    print(req.remote_ip_address)
    print(req.keep_alive)
    
    return response.new(200, "The best engine")
end)

_logging:info("gen_sha256_hash(best_engine) = " .. sha:gen_sha256_hash("best_engine"))
_logging:info("Rules loaded: " .. tostring(yara_instance.rules_loaded_count))

yara_instance:scan_fast_bytes("some_binary_data", function(status, rule, ns)
    if status == 1 then
        _logging:warn("Match encontrado:", rule, "namespace:", ns)
    else
        _logging:info("Nenhum match.")
    end
end)