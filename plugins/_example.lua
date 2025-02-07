local yara_instance = Yara.new()

yara_instance:load_rules(function ()
    yara_instance:load_rules_folder("./rules/")
end)


local config = Configuration.new()
config.path = "plugins/_example.conf"
config:load_logging()

local logging = Logging.new()
logging.config = config
logging:load()

local http_method = HTTPMethod.new()

Web.new(_server, "/engine/status", function (req)
    if(req.method == http_method.Get) then
        return Response.new(200, "The best engine for analysis malware")
    else
        return Response.new(200, "Others method")
    end
    
end, http_method.Post, http_method.Delete, http_method.Get)

local sha = Sha.new()
logging:info("gen_sha256_hash(best_engine) = " .. sha:gen_sha256_hash("best_engine"))
logging:info("Rules loaded: " .. tostring(yara_instance.rules_loaded_count))

yara_instance:scan_fast_bytes("some_binary_data", function(data)
    if data.match == 1 then
        logging:warn("Match encontrado:", data.rule, "namespace:", data.ns)
    else
        logging:info("Nenhum match.")
    end
end)