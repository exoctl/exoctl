#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/database/database.hxx>
#include <engine/focades/analysis/database/entitys.hxx>
#include <engine/logging/logging.hxx>

namespace engine::focades::analysis::database
{
    class Database
    {
      public:
        Database() = default;
        ~Database() = default;

        void setup(configuration::Configuration &, logging::Logging &);
        void load() const;

        [[nodiscard]] const bool analysis_table_exists();
        [[nodiscard]] const std::vector<record::Analysis>
        analysis_table_get_all();
        void analysis_table_insert(const record::Analysis &);
        void analysis_table_update(const record::Analysis &);
        void analysis_table_delete(const record::Analysis &);

        [[nodiscard]] const record::Analysis analysis_table_get_by_id(
            const int);
        [[nodiscard]] const record::Analysis analysis_table_get_by_sha256(
            const std::string &);
        [[nodiscard]] const bool analysis_table_exists_by_sha256(
            const std::string &);

        [[nodiscard]] const bool family_table_exists();
        void family_table_insert(const record::Family &);
        void family_table_update(const record::Family &);
        void family_table_delete(const record::Family &);

        [[nodiscard]] const std::vector<record::Family> family_table_get_all();
        [[nodiscard]] const record::Family family_table_get_by_id(const int);
        [[nodiscard]] const record::Family family_table_get_by_name(
            const std::string &);
        [[nodiscard]] const bool family_table_exists_by_name(
            const std::string &);
        [[nodiscard]] const bool family_table_exists_by_id(const int);

        [[nodiscard]] const bool tag_table_exists();
        void tag_table_insert(const record::Tag &);
        void tag_table_delete(const record::Tag &);
        void tag_table_update(const record::Tag &);

        [[nodiscard]] const std::vector<record::Tag> tag_table_get_all();
        [[nodiscard]] const bool tag_table_exists_by_name(const std::string &);
        [[nodiscard]] const record::Tag tag_table_get_by_id(const int);
        [[nodiscard]] const record::Tag tag_table_get_by_name(
            const std::string &);
        [[nodiscard]] const bool tag_table_exists_by_id(const int);

        [[nodiscard]] const bool analysis_tag_table_exists();
        void analysis_tag_table_insert(const record::AnalysisTag &);
        [[nodiscard]] const std::vector<record::Tag>
        analysis_tag_get_tags_by_analysis_id(const int);
        void analysis_tag_table_delete(const int, const int);

      private:
        configuration::Configuration *config_;
        logging::Logging *log_;
    };
} // namespace engine::focades::analysis::database