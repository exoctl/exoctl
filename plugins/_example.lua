local yara_instance = Yara.new()

yara_instance:load_rules(function ()
    yara_instance:load_rules_folder("./rules/")
end)

local sha = Sha.new()

logging:info("gen_sha256_hash(best_engine) = " .. sha:gen_sha256_hash("best_engine"))


logging:info("Rules loaded: " .. tostring(yara_instance:get_rules_loaded_count()))

yara_instance:scan_fast_bytes("some_binary_data", function(status, rule, ns)
    if status == 1 then
        logging:warn("Match encontrado:", rule, "namespace:", ns)
    else
        logging:info("Nenhum match.")
    end
end)