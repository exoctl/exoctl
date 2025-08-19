#pragma once

#include <stdint.h>
#include <yara.h>

namespace engine::security::yara
{
    namespace type
    {
        enum Flags {
            // Callback message types
            RuleMatching = CALLBACK_MSG_RULE_MATCHING,
            RuleNotMatching = CALLBACK_MSG_RULE_NOT_MATCHING,
            ScanFinished = CALLBACK_MSG_SCAN_FINISHED,
            ImportModule = CALLBACK_MSG_IMPORT_MODULE,
            ModuleImported = CALLBACK_MSG_MODULE_IMPORTED,
            TooManyMatches = CALLBACK_MSG_TOO_MANY_MATCHES,
            ConsoleLog = CALLBACK_MSG_CONSOLE_LOG,
            TooSlowScanning = CALLBACK_MSG_TOO_SLOW_SCANNING,

            // Callback return codes
            ContinueScan = CALLBACK_CONTINUE,
            AbortScan = CALLBACK_ABORT,
            ErrorScan = CALLBACK_ERROR,

            // Scan flags
            FastMode = SCAN_FLAGS_FAST_MODE,
            ProcessMemory = SCAN_FLAGS_PROCESS_MEMORY,
            NoTryCatch = SCAN_FLAGS_NO_TRYCATCH,
            ReportRulesMatching = SCAN_FLAGS_REPORT_RULES_MATCHING,
            ReportRulesNotMatching = SCAN_FLAGS_REPORT_RULES_NOT_MATCHING
        };
        using Rule = YR_RULE;
    } // namespace type
} // namespace engine::security::yara
