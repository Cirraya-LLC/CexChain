// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "registry.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <map>
#include <print>
#include <set>
#include <span>

#include "commands.hpp"
#include "registry_options.hpp"

namespace cexchain::cli {

namespace {

void add_global_options(std::vector<CommandSpec>& specs) {
    for (CommandSpec& spec : specs) {
        auto has = [&](std::string_view name) {
            return std::ranges::any_of(spec.options,
                                       [&](const OptionSpec& o) { return o.name == name; });
        };
        const bool local =
            local_only.contains(spec.path.front()) ||
            (spec.path.size() > 1 && local_only_commands.contains({spec.path[0], spec.path[1]}));
        if (has("ledger") && !local) {
            for (const OptionSpec& option : client_options) {
                if (!has(option.name)) {
                    spec.options.push_back(option);
                }
            }
        }
        spec.options.push_back(json_option);
        spec.options.push_back(help_option);
    }
}

std::string join_path(const CommandSpec& spec) {
    std::string out;
    for (const std::string_view part : spec.path) {
        out += (out.empty() ? "" : " ") + std::string(part);
    }
    return out;
}

const OptionSpec* find_option(const CommandSpec& spec, std::string_view name) {
    const auto it = std::ranges::find(spec.options, name, &OptionSpec::name);
    return it == spec.options.end() ? nullptr : &*it;
}

} // namespace

const std::vector<CommandSpec>& registry() {
    static const std::vector<CommandSpec> specs = [] {
        auto built = program().commands();
        add_global_options(built);
        return built;
    }();
    return specs;
}

std::string command_help(const CommandSpec& spec) {
    const std::string_view me = program().name;
    std::string out =
        std::format("{} {} - {}\n\nUsage: {} {}{}{} [options]\n", me, join_path(spec), spec.summary,
                    me, join_path(spec), spec.arguments.empty() ? "" : " ", spec.arguments);
    if (!spec.details.empty()) {
        out += "\n" + std::string(spec.details) + "\n";
    }
    out += "\nOptions:\n";
    for (const OptionSpec& option : spec.options) {
        std::string left = "  --" + std::string(option.name);
        if (!option.value.empty()) {
            left += " " + std::string(option.value);
        }
        std::string notes;
        if (option.required) {
            notes += " [required]";
        }
        if (option.repeatable) {
            notes += " [repeatable]";
        }
        out += std::format("{:<30} {}{}\n", left, option.help, notes);
    }
    return out;
}

std::string overview_help() {
    std::string out(program().overview);
    std::string group;
    for (const CommandSpec& spec : registry()) {
        if (spec.alias) {
            continue;
        }
        if (spec.group != group) {
            group = spec.group;
            out += "\n" + group + ":\n";
        }
        std::string name = join_path(spec);
        if (!spec.arguments.empty()) {
            name += " " + std::string(spec.arguments);
        }
        out += std::format("  {:<34} {}\n", name, spec.summary);
    }
    return out;
}

std::string completion_script(std::string_view shell) {
    // Words that may follow each command prefix, and options per full command.
    std::map<std::string, std::set<std::string>> next;
    std::map<std::string, std::vector<std::string>> options;
    for (const CommandSpec& spec : registry()) {
        std::string prefix;
        for (const std::string_view part : spec.path) {
            next[prefix].insert(std::string(part));
            prefix += (prefix.empty() ? "" : " ") + std::string(part);
        }
        for (const OptionSpec& option : spec.options) {
            options[prefix].push_back("--" + std::string(option.name));
        }
    }
    std::string cases;
    for (const auto& [prefix, words] : next) {
        std::string list;
        for (const std::string& w : words) {
            list += (list.empty() ? "" : " ") + w;
        }
        cases += std::format("        \"{}\") words=\"{}\" ;;\n", prefix, list);
    }
    std::string option_cases;
    for (const auto& [command, names] : options) {
        std::string list;
        for (const std::string& n : names) {
            list += (list.empty() ? "" : " ") + n;
        }
        option_cases += std::format("        \"{}\") opts=\"{}\" ;;\n", command, list);
    }
    // One function per program: cexchain-index completes as _cexchain_index.
    std::string function = "_" + std::string(program().name);
    std::ranges::replace(function, '-', '_');
    std::string script = std::format(R"(# {0} completion
{1}() {{
    local cur prefix words opts i w
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prefix=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        w="${{COMP_WORDS[i]}}"
        [[ "$w" == -* ]] && break
        prefix="${{prefix:+$prefix }}$w"
    done
    words=""
    case "$prefix" in
{2}    esac
    opts=""
    case "$prefix" in
{3}    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    elif [[ -n "$words" ]]; then
        COMPREPLY=($(compgen -W "$words" -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}}
)",
                                     program().name, function, cases, option_cases);
    if (shell == "zsh") {
        return "autoload -U +X bashcompinit && bashcompinit\n" + script +
               std::format("complete -o filenames -F {} {}\n", function, program().name);
    }
    if (shell == "bash") {
        return script + std::format("complete -o filenames -F {} {}\n", function, program().name);
    }
    throw UsageError{"shell must be bash or zsh"};
}

int dispatch(int argc, const char* const* argv) {
    std::vector<std::string> tokens(argv + 1, argv + argc);
    // The command is the longest registered path matching the leading words.
    const CommandSpec* spec = nullptr;
    for (const CommandSpec& candidate : registry()) {
        if (candidate.path.size() > tokens.size()) {
            continue;
        }
        const bool matches =
            std::ranges::equal(candidate.path, std::span(tokens).first(candidate.path.size()),
                               [](std::string_view a, const std::string& b) { return a == b; });
        if (matches && (spec == nullptr || candidate.path.size() > spec->path.size())) {
            spec = &candidate;
        }
    }
    if (spec == nullptr) {
        if (tokens.empty() || tokens[0] == "--help" || tokens[0] == "-h") {
            std::print("{}", overview_help());
            return tokens.empty() ? 1 : 0;
        }
        if (tokens[0] == "--version") {
            return cmd_version(Args(registry().front(), {}, {}));
        }
        // A command group without a subcommand: list the group.
        std::string group;
        std::string suggestion;
        for (const CommandSpec& candidate : registry()) {
            if (candidate.path.size() > 1 && candidate.path.front() == tokens[0]) {
                group += std::format("  {} {:<30} {}\n", program().name, join_path(candidate),
                                     candidate.summary);
            }
            if (candidate.path.back() == tokens[0]) {
                suggestion += (suggestion.empty() ? "" : std::format("' or '{} ", program().name)) +
                              join_path(candidate);
            }
        }
        if (!group.empty()) {
            const bool asked = tokens.size() > 1 && (tokens[1] == "--help" || tokens[1] == "-h");
            std::print("{}", group);
            if (!asked && tokens.size() > 1) {
                throw UsageError{"unknown command '" + tokens[0] + " " + tokens[1] + "'"};
            }
            return asked ? 0 : 1;
        }
        const std::string me(program().name);
        throw UsageError{
            "unknown command '" + tokens[0] + "'" +
            (suggestion.empty() ? "" : "; did you mean '" + me + " " + suggestion + "'?") +
            " Run " + me + " --help"};
    }

    std::vector<std::string> positional;
    std::multimap<std::string, std::string, std::less<>> options;
    for (std::size_t i = spec->path.size(); i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (!token.starts_with("--")) {
            positional.push_back(token);
            continue;
        }
        std::string name = token.substr(2);
        std::optional<std::string> value;
        if (const auto eq = name.find('='); eq != std::string::npos) {
            value = name.substr(eq + 1);
            name.resize(eq);
        }
        const OptionSpec* option = find_option(*spec, name);
        if (option == nullptr) {
            throw UsageError{"unknown option --" + name + " for '" + std::string(program().name) +
                             " " + join_path(*spec) + "'; run it with --help"};
        }
        if (option->value.empty()) {
            if (value) {
                throw UsageError{"option --" + name + " takes no value"};
            }
            value = "";
        } else if (!value) {
            if (i + 1 >= tokens.size()) {
                throw UsageError{"option --" + name + " needs a value (" +
                                 std::string(option->value) + ")"};
            }
            value = tokens[++i];
        }
        if (!option->repeatable && options.contains(name)) {
            throw UsageError{"option --" + name + " given more than once"};
        }
        options.emplace(name, *value);
    }
    if (options.contains("help")) {
        std::print("{}", command_help(*spec));
        return 0;
    }
    for (const OptionSpec& option : spec->options) {
        if (option.required && !options.contains(option.name)) {
            throw UsageError{"missing required option --" + std::string(option.name) + " for '" +
                             std::string(program().name) + " " + join_path(*spec) + "'"};
        }
    }
    if (positional.size() < spec->min_arguments || positional.size() > spec->max_arguments) {
        throw UsageError{"usage: " + std::string(program().name) + " " + join_path(*spec) +
                         (spec->arguments.empty() ? "" : " " + std::string(spec->arguments)) +
                         " [options]"};
    }
    if (program().before_run != nullptr) {
        program().before_run();
    }
    return spec->run(Args(*spec, std::move(positional), std::move(options)));
}

} // namespace cexchain::cli
