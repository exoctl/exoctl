logging:info(tostring(engine.is_running))

local yara_instance = Yara.new()

yara_instance:load_rules(function ()
    yara_instance:load_rules_folder("rules/")    
end)

print("Rules loaded: ", yara_instance:get_rules_loaded_count())

yara_instance:scan_fast_bytes("some_binary_data", function(status, rule, ns)
    if status == 1 then
        print("Match encontrado:", rule, "namespace:", ns)
    else
        print("Nenhum match.")
    end
end)
