-- Acessando uma propriedade (como 'is_running')
logging:info(tostring(engine.is_running))


-- Carregar regras
yara_instance = Yara.new()

-- Carregando regras de um diretório
yara_instance:load_rules_folder("rules/rules-yara")

print("Rules loaded: ", yara_instance:get_rules_loaded_count())

-- Fazendo um scan rápido de um buffer
yara_instance:scan_fast_bytes("some_binary_data", function(status, rule, ns)
    if status == 1 then
        print("Match encontrado: ", rule, "namespace:", ns)
    else
        print("Nenhum match.")
    end
end)
