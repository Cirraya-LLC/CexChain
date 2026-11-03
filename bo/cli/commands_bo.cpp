// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// bo's commands: the table the registry dispatches, documents, and
// completes from.

#include "commands.hpp"
#include "registry_options.hpp"

namespace cexchain::cli {

namespace {

const OptionSpec pack_option{"pack", "FILE", "Read source with this language pack too", false,
                             true};
const OptionSpec vocab_option{
    "vocab", "FILE",
    "Read source with this vocabulary pack of your own too (a .vocab file, or a directory's)",
    false, true};
const OptionSpec hash_option{"hash", "HASH", "Digests with sha256 (default) or sm3"};
const OptionSpec memory_option{"max-memory", "MIB",
                               "Run with at most this much memory, in MiB (the console runs the "
                               "compiler so)"};
const OptionSpec language_option{
    "language", "LANG",
    "Messages in en, zh-Hant-HK, zh-Hans-CN, or a given pack's language (default: "
    "$CEXCHAIN_LANGUAGE, else en)"};

/// What every Bo command says about where it exists.
#define CEXCHAIN_BO_PACKS_HELP                                                                     \
    "A language pack maps Bo's concepts (kw.can, act.transfer, unit.GB) to one language's\n"       \
    "spellings and gives its reading rules, messages, and sentences; it never changes what\n"      \
    "runs. The official packs (English, Traditional Chinese in Hong Kong usage, Simplified\n"      \
    "Chinese) are always read; a Bo deploy records each pack's digest (the hash of its\n"          \
    "canonical CBOR), and that of each vocabulary pack its use lines name (bo vocab list).\n"      \
    "The bo commands exist only in builds with the Bo compiler, which needs GCC 16 (C++26\n"       \
    "reflection and contracts)."

} // namespace

std::vector<CommandSpec> bo_commands() {
    return {
        // ------------------------------------------------------------------
        {{"version"}, "Print the version", "General", "", 0, 0, {}, cmd_bo_version},
        {{"help"}, "Show help for a command", "General", "[COMMAND...]", 0, 3, {}, cmd_help},
        {{"completion"},
         "Print a shell completion script",
         "General",
         "bash|zsh",
         1,
         1,
         {},
         cmd_completion,
         "Load with: source <(cexchain completion bash)   or   source <(cexchain completion zsh)"},

        // ------------------------------------------------------------------
        {{"check"},
         "Check a Bo source file; with --stage, show its tokens, its tree, or its model",
         "Bo language",
         "FILE",
         1,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               language_option,
               {"stage", "STAGE",
                "Show what a stage reads: lex (the tokens, with their places), parse (the "
                "tree), or model (the checked model)"}}),
         cmd_bo_check,
         "Reads FILE (UTF-8) with the official language packs and any given with --pack, and\n"
         "reports every problem (up to 100 per stage) as FILE:LINE:COLUMN: error: message\n"
         "(code), in the language of --language. Exit status 2 if there is an error;\n"
         "warnings (a fragment, notify declared as an action, a rule for answers to requests\n"
         "the contract never makes) do not fail.\n\n"
         "The lexer reads lines and indentation (spaces only), # comments, words under the\n"
         "packs' rules (可轉讓 is 可 + 轉讓; 每GB is 每 + GB; a word with two readings is an\n"
         "error, since Bo never guesses), names, numbers (5_000_000, 0.10, 500萬, full-width\n"
         "digits), money with its currency on either side (HKD 0.10), quantities (2TB, 3 噸,\n"
         "1個), durations (30日), percentages (5%), dates (2027-01-06, 2027年1月6日), texts in\n"
         "double quotes, and the edition line (bo 1). Invisible characters, and in names\n"
         "anything Unicode normalization would change, are refused, so that two names that\n"
         "look alike are never different.\n\n"
         "The parser reads the clauses: use PACK (the vocabulary packs the source uses);\n"
         "contract NAME; parties; a kind and its fields (thing Camera, then holder owner); can\n"
         "ACTION with by, to, with, and a block of requires,\n"
         "if/otherwise, each, reject, FIELD = VALUE, state changes (active -> suspended), and\n"
         "actions; when EVENT ACTION; test blocks of steps (owner lend to friend1 at\n"
         "2027-01-06) and expectations (-> lent, -> refused). Conditions use not, and, or,\n"
         "the comparisons = < <= > >= and in, then + -, then * /.\n\n"
         "The checker reads the tree into a model: the parties and how each is bound (at\n"
         "creation, or by the action that first names it after to), the one kind of instance\n"
         "and its fields (a type: each instance's own; a value: a constant; a party: a field\n"
         "that starts with it), the states (from the state changes; an instance starts in the\n"
         "one state nothing leads to, else in active), the actions, and the time rules. It\n"
         "checks names, types and units (money never mixes currencies, quantities never mix\n"
         "dimensions, months never mix with days, every value exact in its smallest unit),\n"
         "bounded lists, no recursion, reachable states, thresholds (over N takes the unit of\n"
         "the action's one amount), and where in person may stand. What it infers carries the\n"
         "id of its rule (R1, R2, ...; the packs' sentences rule-R1 ... explain each). A word\n"
         "of a vocabulary pack the source does not use is an error (check.pack-not-used): add\n"
         "use PACK at the top (bo vocab list shows the packs and their words).\n\n"
         "--stage lex prints one token per line: LINE:COLUMN KIND VALUE | as written. A word\n"
         "is its concept (kw.can, act.transfer), the same in every language; a word with an\n"
         "argument's place comes in pieces (consent of: piece=head; before due: piece=tail;\n"
         "經 ... 同意: piece=open and piece=close).\n\n"
         "--stage parse prints the tree: one clause or statement per line, expressions as\n"
         "S-expressions of concepts and names, the same for the same contract in any\n"
         "language. With --json, also the tree as objects with their places.\n\n"
         "--stage model prints the checked model: one declaration or statement per line, with\n"
         "{R3} after what a rule inferred, the same in any language. With --json, also the\n"
         "model as objects (types as text: money cur.HKD), with their places.\n\n"
         "  bo check contract.bo\n"
         "  bo check contract.bo --stage model\n"
         "  bo check contract.bo --stage parse\n"
         "  bo check contract.bo --stage lex --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"build"},
         "Build a Bo contract: its code, interface, and the source bundle a deploy records",
         "Bo language",
         "FILE",
         1,
         1,
         with(
             {vocab_option,
              memory_option,
              pack_option,
              language_option,
              {"hash", "HASH",
               "Pack digests with sha256 (default) or sm3: the hash of the ledger it goes to"},
              {"out", "FILE", "Write the built contract here (FILE.boc), for contract deploy --bo"},
              {"code-out", "FILE", "Write the module (WebAssembly) here"},
              {"bundle-out", "FILE", "Write the bo-source bundle here"},
              {"fuel", "", "Show each function's bound: fuel, reading the input, and output"}}),
         cmd_bo_build,
         "Checks FILE as bo check does, then compiles it to a module in the contract profile\n"
         "(spec section 14) with one function per action plus the one that creates an instance\n"
         "(create; a vocabulary pack's kind may name its own), and makes the bo-source bundle a\n"
         "deploy records: the source as written, comments included (a warning says so: every\n"
         "party and verifier reads them), its edition, each language pack it was read with\n"
         "(id, version, and the digest of its canonical CBOR under --hash; packs that are not\n"
         "official, in full), and each vocabulary pack its use lines name (id, version,\n"
         "digest). The same source gives the\n"
         "same bytes in any language and on any machine; the compiler string (cexchain-bo\n"
         "RELEASE; codegen N; edition E) names what built it. A fragment (no contract line) does\n"
         "not build, nor notify declared as an action (it is a request). Exit status 2 if it\n"
         "does not build.\n\n"
         "Fuel. Each function's worst case comes from the code's structure: every loop bounded\n"
         "by what the contract bounds (lists, the lines and charges of a bill it computes, the\n"
         "parts and consents of a split), sizes by the input's limits. It holds for any call\n"
         "whose arguments are of the function's shape, on any state the contract writes. A\n"
         "contract any of whose functions could need more than the 10,000,000 fuel a call has\n"
         "does not build (build.fuel); one whose output could exceed the 196,608 bytes the code\n"
         "has for it builds with a warning (build.output). The text shows the highest bound;\n"
         "--fuel shows every function's: its fuel, the part reading the input takes, and its\n"
         "output.\n\n"
         "Without --out, nothing is written: it reports the code's size and hash. Deploy with\n"
         "contract deploy --bo FILE.bo (which builds again) or FILE.boc.\n\n"
         "  bo build contract.bo\n"
         "  bo build contract.bo --fuel\n"
         "  bo build contract.bo --out contract.boc --hash sm3\n"
         "  bo build contract.bo --json\n"
         "  bo build contract.bo --code-out contract.wasm\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"rebuild"},
         "Rebuild a deployed contract from its source and compare it with its code",
         "Bo language",
         "DEPLOY",
         1,
         1,
         with({memory_option,
               {"require", "", "Fail (exit 3) unless it rebuilds, also for another compiler's"}}),
         cmd_bo_rebuild,
         "DEPLOY is a deploy file: cexchain contract export writes one of a deployed contract,\n"
         "bo build --out of a built one. The source it carries (a bo-source bundle) is opened\n"
         "with the packs it names, under the hash the file names, built again, and compared\n"
         "with the code, the interface, and the name:\n"
         "  rebuilds          the source builds to the code, interface, and name\n"
         "  DOES NOT REBUILD  with the compiler the deploy names, it builds to something else:\n"
         "                    the source is not the code's (exit 3)\n"
         "  MALFORMED         no source, or not a bo-source bundle, or packs that do not check\n"
         "                    (exit 3)\n"
         "  not rebuilt       another compiler or version built it, whose output this one does\n"
         "                    not reproduce (it names the release to use); --require fails it\n\n"
         "  cexchain contract export 3f2a9c1e --out deal.boc && bo rebuild deal.boc"},
        {{"reason"},
         "Say a compiled Bo contract's reason for refusing a call, in words",
         "Bo language",
         "REASON",
         1,
         1,
         with({pack_option,
               {"language", "LANG",
                "In en, zh-Hant-HK, zh-Hans-CN, or a given pack's language (default: "
                "$CEXCHAIN_LANGUAGE, else en)"}}),
         cmd_bo_reason,
         "A compiled contract refuses with a short reason, such as bo:state countersign or\n"
         "bo:requires sign 2, which the ledger and cexchain show as given; this says it in the\n"
         "reader's language.\n\n"
         "  bo reason 'bo:state countersign' --language zh-Hant-HK"},
        {{"explain"},
         "Write the contract text of a Bo source or deploy, in English or Chinese, with every "
         "inferred rule",
         "Bo language",
         "FILE",
         1,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG",
                "The text (and messages) in en, zh-Hant-HK, zh-Hans-CN, or a given pack's "
                "language (default: $CEXCHAIN_LANGUAGE, else en)"},
               {"state", "FILE",
                "With a deploy file: an instance's state (CBOR, cexchain contract instance "
                "--state-out), in the text's words"}}),
         cmd_bo_explain,
         "Checks FILE as bo check does, then writes its contract text: what the parties read\n"
         "and confirm before they sign. It covers the parties and when each is bound to a\n"
         "ledger; what each instance records (its kind, its fields, and how one is created);\n"
         "charges; the states (the first, the final ones, from which no action can start, and\n"
         "the events); each action (who starts it, its inputs, the consents it needs, its\n"
         "requirements numbered as compiled code numbers them in a refusal such as\n"
         "bo:requires sign 2, its choices, refusals, field and state changes, and what AI\n"
         "agents may do); the time rules (what is due, duties, executors); and the rules Bo\n"
         "applied. Bo never guesses, and what it infers instead of reading it (a role bound by\n"
         "an action, a consent an action needs, the first state, a threshold's unit) is\n"
         "spelled out in the clause and marked with its rule, such as [R3]; the last section\n"
         "explains each rule used. Texts are shown in quotation marks, including a name Bo\n"
         "read as a text by rule R18 (color = red shows as: color is \"red\").\n\n"
         "The text depends only on the contract and the language: a contract written in\n"
         "English, in Chinese, or in both gives the same text, byte for byte. Problems go to\n"
         "stderr (warnings do not stop the text); exit status 2 if the source does not check.\n"
         "With --json: the text, and its sections and clauses, each with its number, its\n"
         "rules, and (for an action) its function. Once deployed, contract explain writes the\n"
         "same text from the deploy.\n\n"
         "  bo explain contract.bo\n"
         "  bo explain contract.bo --language zh-Hant-HK\n"
         "  bo explain contract.bo --language zh-Hans --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"fmt"},
         "Lay out a Bo source canonically, or write it in one language",
         "Bo language",
         "FILE",
         1,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG",
                "Write every keyword and word in en, zh-Hant-HK, zh-Hans-CN, or a given pack's "
                "language (messages too); without it, words keep their spelling"},
               {"check", "", "Change nothing; exit status 3 if formatting would change FILE"},
               {"write", "", "Write the result back to FILE"}}),
         cmd_bo_fmt,
         "Prints FILE in canonical layout: two spaces per block, one space between words\n"
         "(none before , and ) or after (), comments kept where they are (a comment after code\n"
         "two spaces after it), runs of blank lines as one, digits in ASCII, full-width\n"
         "punctuation (，、) kept without spaces around it, and\n"
         "Chinese written as Chinese is: a prefix keyword joined to the word after it (可轉讓,\n"
         "須親身確認), an attaching word to its neighbour (30日內), a number to its\n"
         "multiplier and its Chinese unit or currency (500萬港元, 30日); Latin words and numbers\n"
         "stand apart from Chinese by a space (每 GB).\n\n"
         "With --language, every keyword and word not already spelled in that language is\n"
         "written in its first spelling there (a unit after a number other than 1 in its plural\n"
         "form: 30 days), and a word with an argument is arranged as that language spells it\n"
         "(consent of counterparty, 經 相對方 同意). Names the contract gives, texts in quotes, "
         "and\n"
         "comments stay as written; a multiplier the language lacks is written out (500萬 is\n"
         "5_000_000 in English). A contract written in Chinese can so be handed to an\n"
         "English-speaking counterparty as English source: it parses to the same tree, checks to\n"
         "the same model, builds to the same code, and explains to the same text. Formatting\n"
         "again changes nothing. The text is not reversible: forms and other spellings become\n"
         "the first spelling (transfers, then 轉讓, then transfer), and multipliers stay written\n"
         "out.\n\n"
         "The result is read again before it is printed or written: it must give the same tree\n"
         "and comments. If a name the contract gives would read together with the new\n"
         "language's words, nothing is formatted (fmt.unstable says where). Source with errors\n"
         "is not formatted (exit status 2, problems on stderr). --check changes nothing and exits\n"
         "3 if FILE is not formatted (in that language, with --language); --write writes it\n"
         "back. With --json: ok, changed, written, the source, and any problems.\n\n"
         "  bo fmt contract.bo\n"
         "  bo fmt contract.bo --language zh-Hant-HK\n"
         "  bo fmt contract.bo --language en --write\n"
         "  bo fmt contract.bo --check --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"form"},
         "Write a Bo source from a rules sheet, or read a source back into one",
         "Bo language",
         "[SHEET]",
         0,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG",
                "Write the source in en, zh-Hant-HK, zh-Hans-CN, or a given pack's language "
                "(messages too)"},
               {"out", "FILE", "Write the source (or, with --from, the sheet) here"},
               {"from", "SOURCE", "Read a Bo source back into a rules sheet"}}),
         cmd_bo_form,
         "A rules sheet (JSON, \"sheet\": 1, \"kind\": \"rules\") describes a contract with\n"
         "what a form can hold: its parties; its kind and fields; its actions (by, to, inputs,\n"
         "requirements, consents, in person, a threshold for presence, whether AI agents may\n"
         "only propose, the state change, the fields set, the requests); its time rules; its\n"
         "rules for answers; and its tests. Everything that is not a choice of the form is a\n"
         "piece of Bo as written: names in any language, types (HKD, date), values, conditions,\n"
         "events. bo form writes the source, every keyword around those pieces and nothing else\n"
         "(Bo never guesses), in canonical layout and, with --language, in that language, then\n"
         "checks it: each problem is named by its place in the sheet (SHEET:/actions/0/set/1).\n"
         "Exit status 2 if the sheet is not one, or its source does not check.\n\n"
         "--from SOURCE reads a source back into a sheet, its pieces as written, when every\n"
         "construct fits the form (no choices, loops, refusals, or lines in another order); a\n"
         "source that does not fit says why, and stays text. Writing that sheet again gives the\n"
         "same tree.\n\n"
         "  bo form lending.json\n"
         "  bo form lending.json --language zh-Hant-HK --out lending.bo\n"
         "  bo form --from lending.bo --out lending.json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"calls"},
         "List what each call of a contract takes, for a form",
         "Bo language",
         "FILE",
         1,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG",
                "Labels, types, and clauses in en, zh-Hant-HK, zh-Hans-CN, or a given pack's "
                "language (default: $CEXCHAIN_LANGUAGE, else en)"},
               {"state", "HEX", "Also an instance's state (its CBOR, in hex), in words"},
               {"label", "LEDGER=NAME", "With --state: name this ledger (its id in hex)", false,
                true}}),
         cmd_bo_calls,
         "FILE is a Bo source, or a built contract (.boc, as bo build --out writes it and a\n"
         "deploy records it), read with the packs its bundle names. Lists the contract's calls\n"
         "in the order of its interface: the creation (the fields given at creation, each\n"
         "required or with its default, and the roles bound at creation), each action (its\n"
         "inputs, the role it binds to the ledger a call names, whether AI agents only propose\n"
         "it, and its clauses of the contract text), approve, the time rules, and the reply to\n"
         "requests. Each value has its name in the call's arguments, its label and type in the\n"
         "reader's language, and where it goes (a field, a role, or an input). --state shows an\n"
         "instance's state as the contract text writes it.\n\n"
         "  bo calls lending.bo\n"
         "  bo calls lending.boc --language zh-Hant-HK --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"args"},
         "Build a call's arguments from values written as a person would",
         "Bo language",
         "FILE FUNCTION",
         2,
         2,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG", "Messages in en, zh-Hant-HK, zh-Hans-CN"},
               {"values", "JSON", "The values: {\"NAME\": VALUE, ...}"},
               {"set", "NAME=VALUE", "One value, as text (repeatable)", false, true}}),
         cmd_bo_args,
         "Builds the arguments of a call of FUNCTION (the creation, or an action) on the\n"
         "contract in FILE (a source or a .boc), as spec/bo.md section 12.4 defines them, from\n"
         "values by name, as bo calls lists them. A text is taken as typed; yes or no is true or\n"
         "false; a party is its ledger id (64 hexadecimal digits); a list is a JSON array; a\n"
         "number, money, a quantity, a rate, a date, or a duration is written as Bo writes it, in\n"
         "any language (HKD 100.50, 500萬, 2027年1月6日, 30日), and checked against the declared\n"
         "type. A plain number is in the field's currency for money, in the declared unit for a\n"
         "quantity that names one, and in percent for a rate. Prints the arguments in CBOR\n"
         "diagnostic notation, for contract create --args and contract call --args; each\n"
         "problem names its value and a code (missing, unknown, type, literal, exact, ledger,\n"
         "bound, size, twice, function). Exit status 2 if there is one.\n\n"
         "  bo args lending.bo create --set \"name=Camera X100\" --set owner=3f2a...\n"
         "  bo args lending.bo lend --values '{\"counterparty\": \"8d01...\"}' "
         "--json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"test"},
         "Run the test blocks of a Bo source: each scenario, step by step, as a ledger would",
         "Bo language",
         "FILE",
         1,
         1,
         with({vocab_option,
               memory_option,
               pack_option,
               {"language", "LANG",
                "The report (and messages) in en, zh-Hant-HK, zh-Hans-CN, or a given pack's "
                "language (default: $CEXCHAIN_LANGUAGE, else en)"}}),
         cmd_bo_test,
         "Builds FILE as bo build does, then runs each of its test blocks on the compiled code\n"
         "exactly as a ledger runs calls (each call's input and output as spec section 15\n"
         "defines them). Each test creates its own instance and runs its steps in order; it\n"
         "stops at the first step that fails. A test block:\n\n"
         "  test \"only the holder brings it back\"\n"
         "    owner create with name = \"Camera X100\"\n"
         "    owner lend to friend1 -> lent\n"
         "    owner lend to friend2 -> refused \"bo:state lend\"\n"
         "    friend2 bring_back -> consent of friend1\n"
         "    friend1 bring_back at 2027-01-05 -> active\n\n"
         "A step is PARTY ACTION [to PARTY] [with INPUT = VALUE, ...] [at DATE] [in person]\n"
         "[by AI agent] [-> EXPECTATION]. The first step creates the instance (create, or the\n"
         "word a vocabulary pack's kind creates with), and its party is the home, whose ledger\n"
         "runs the contract\n"
         "(we, if the contract has that role). Every party is a test ledger of its own; a name\n"
         "the contract does not declare (friend1) is a ledger only the test names, which to may\n"
         "bind a role to. Values are written as in the source (HKD 5_000, 2027-01-06, 30 days,\n"
         "\"text\", yes). A step happens at the time of the step before it, or on the day at\n"
         "names (local midnight at the contract's UTC offset, +08:00 unless it names one); a\n"
         "test starts on 2026-01-01, or on its first at date if that is earlier. in person signs\n"
         "as a person who proves presence, by AI agent as an AI agent, and otherwise the\n"
         "party itself signs. keeper ACTION [at DATE] calls the time rule that does ACTION\n"
         "(when.ACTION), as the home's keeper, a device: keeper suspend at 2027-07-03 ->\n"
         "suspended; before its time it is refused (bo:when when.suspend).\n\n"
         "Parts: once a split has made parts (each an instance of its own), a step acts on the\n"
         "one its party holds, or that another of its party fields names; or on the one the\n"
         "party it names after the action holds (we cancel maker1). Of those, the one that takes\n"
         "calls, else the one final instance (a divided parent refuses). A party holding several\n"
         "fails the step. Recipients are the test's parties: owner split with parts = (HKD 600,\n"
         "HKD 400), recipients = (maker1, maker2) -> divided. The report names each part by its\n"
         "path: part 1.2 is the second part of the first part.\n\n"
         "Consents: a call runs first without any, as the home runs it to learn whom to ask;\n"
         "then every party the contract asks consents, and it runs again. Parties that do not\n"
         "consent: those the expectation names (-> consent of friend1), and, when the step's\n"
         "party is not the one that starts the action (by), the one that does (the home agrees\n"
         "only by making a call itself). Expectations: -> STATE (accepted, and the instance is\n"
         "in that state), -> refused, -> refused \"REASON\" (the reason exactly as the contract\n"
         "gives it: a reject's text, or a code such as bo:requires sign 2), -> consent of PARTY\n"
         "(the call waits for that consent; consent of (A, B) for two). A step without one\n"
         "expects its call to be accepted. An expectation of an accepted call may also name\n"
         "values of instance fields after the call, after a comma or alone: -> delivered,\n"
         "fee = HKD 4_000; -> count = 2. The step fails if a field holds another value, and\n"
         "the report gives both.\n\n"
         "The report shows each step as written, what it expected if it failed, what\n"
         "happened (worded in --language), and for a refusal the clause of the contract text\n"
         "it comes from. The results are the same whatever language the contract and its\n"
         "tests are written in. Exit status 3 if a test fails, 2 if the source does not\n"
         "build. With --json: each test and step, what it expected and what happened (the\n"
         "part it acted on, the parts a call made, the expected fields' values and those that\n"
         "differ), and its calls with their consents, fuel, and input.\n\n"
         "  bo test contract.bo\n"
         "  bo test contract.bo --language zh-Hant-HK\n"
         "  bo test contract.bo --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"packs", "list"},
         "List the language packs Bo source is read with, and their digests",
         "Bo language",
         "",
         0,
         0,
         with({pack_option, hash_option, language_option}),
         cmd_bo_packs_list,
         CEXCHAIN_BO_PACKS_HELP},
        {{"packs", "show"},
         "Show a language pack: its reading rules, keywords, words, messages, and sentences",
         "Bo language",
         "PACK",
         1,
         1,
         with({pack_option,
               hash_option,
               language_option,
               {"section", "NAME",
                "Show one part: reading, keywords, vocabulary, messages, or sentences"}}),
         cmd_bo_packs_show,
         "PACK is a pack's id (en, zh-Hant-HK, zh-Hans-CN, or one given with --pack) or a\n"
         "pack file.\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"packs", "check"},
         "Check language pack files, alone and with the official packs",
         "Bo language",
         "FILE...",
         1,
         64,
         with({language_option}),
         cmd_bo_packs_check,
         "Reports every problem in each file (up to 100), then reads the files together with\n"
         "the official packs, as a source would be read: one spelling with two meanings, or a\n"
         "word an attaching rule could split two ways, is an error (Bo never guesses). Exit\n"
         "status 2 if any pack has an error; warnings (words left to English) do not fail.\n\n"
         "A pack is a file in CBOR diagnostic notation, with # and / ... / comments:\n"
         "  {\"format\": 1, \"id\": \"ja\", \"version\": 1, \"language\": \"ja\",\n"
         "   \"name\": \"日本語\", \"official\": false, \"edition\": 1,\n"
         "   \"reading\": {\"separation\": \"none\", \"prefixes\": [...], \"attach\": [...],\n"
         "               \"punctuation\": {...}, \"multipliers\": {...}, \"dates\": {...}},\n"
         "   \"keywords\": {\"kw.can\": \"...\", ...},       every keyword\n"
         "   \"vocabulary\": {\"act.transfer\": \"...\", ...},  any words; English fills in\n"
         "   \"messages\": {...}, \"sentences\": {...}}\n"
         "bo packs show en --json lists every concept id; the official packs in the source\n"
         "tree (bo/packs/) are complete examples.\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"stdlib", "list"},
         "List the built-in actions of Bo's standard library, with who starts each and its states",
         "Bo language",
         "[PACK]",
         0,
         1,
         with({vocab_option, language_option}),
         cmd_bo_stdlib_list,
         "Bo's standard library (bo/stdlib/, compiled in) writes the built-in actions in Bo\n"
         "itself, each with its standard terms: the core's (transfer, cancel, suspend, resume,\n"
         "terminate), then those of each vocabulary pack, which a contract uses after its use\n"
         "line (bo vocab show PACK). A contract that writes can transfer to\n"
         "counterparty gets the library's transfer (rule R19): started by the holder, with the\n"
         "consent of the holder and the counterparty, only from active, making the counterparty\n"
         "the holder. The lines the contract writes under it add to the terms and are checked\n"
         "first; without to, each call names the counterparty (R21). To change a built-in\n"
         "action, copy it under a name of your own (bo stdlib show ACTION prints it).\n\n"
         "Each line: the function, its pack (core, or a vocabulary pack), the action's word in\n"
         "--language, who starts it (or the home, on its own word), its counterparty, and the\n"
         "states it starts from and leads to. With PACK (core, or a vocabulary pack's id),\n"
         "only that pack's. With --json: each action's function, pack, concept, starter,\n"
         "counterparty, and states.\n\n"
         "  bo stdlib list\n"
         "  bo stdlib list core\n"
         "  bo stdlib list --language zh-Hant-HK --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"stdlib", "show"},
         "Show a built-in action's terms: its Bo source, to copy, and its contract text",
         "Bo language",
         "ACTION",
         1,
         1,
         with({vocab_option, pack_option, language_option}),
         cmd_bo_stdlib_show,
         "ACTION is a built-in action's word in any language (transfer, 轉讓, 转让) or its\n"
         "function (confirm_payment). Prints the action's terms as Bo source, in --language,\n"
         "without the library's comments (after the use line of its vocabulary pack, if it has\n"
         "one), and then the contract text that states them, each\n"
         "clause with its rules (R19 marks the standard terms). To change a built-in action,\n"
         "copy the source into a contract and give the action a name of your own: it is then\n"
         "the contract's own action, checked and explained like any other. With --json: the\n"
         "pack, the source, and each clause of the text with its kind and rules.\n\n"
         "  bo stdlib show transfer\n"
         "  bo stdlib show 轉讓 --language zh-Hant-HK\n"
         "  bo stdlib show confirm_payment --json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"vocab", "check"},
         "Check vocabulary pack files of your own: alone, then with the official packs",
         "Bo language",
         "FILE...",
         1,
         64,
         with({vocab_option, pack_option, language_option}),
         cmd_bo_vocab_check,
         "Reads each FILE, a vocabulary pack of your own (CBOR diagnostic notation, like a\n"
         "language pack): its id (lowercase ASCII letters, digits, and _; not core nor an\n"
         "official pack's), version, and edition; the packs it requires; its concepts, each an\n"
         "action, a field (with its type: party, date, number, text, duration, parties,\n"
         "quantity, list, or amount; a party field may be added, R20, or taking, R31), a state,\n"
         "a role, or a unit (of a dimension of the core's: data, bandwidth, count, mass, or\n"
         "temperature, and its scale); the standard terms of its actions, in Bo; and in each\n"
         "language (by language pack id) its name and every word's spellings. Then reads them\n"
         "together with the official packs, the vocabulary packs given with --vocab, and the\n"
         "language packs given with --pack, as a source would: every spelling new, every\n"
         "required pack there, and the terms reading as Bo, each clause a can of one of the\n"
         "pack's actions, with words of the core, the pack, and the packs it requires. Every\n"
         "problem is reported, with its code (vocab.*, pack.*). A concept's plain name may not\n"
         "be that of a core or official word of its category: compiled code names it so.\n\n"
         "Each line: the file, the pack's id and version, its words by category, its actions\n"
         "with terms, and its languages. Exits 2 if a pack does not read. With --json: each\n"
         "file's problems and facts, and those of the packs together.\n\n"
         "  bo vocab check events.vocab\n"
         "  bo vocab check events.vocab --language zh-Hant-HK --json\n\n"
         "Packs of your own are files: nothing is created on a ledger, and nothing is revoked.\n"
         "A source uses one with a use line and --vocab FILE on every bo command (and on\n"
         "contract deploy --bo); a deploy embeds it in the contract's source bundle, so anyone\n"
         "rebuilds the contract without the file.\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"vocab", "list"},
         "List Bo's core vocabulary and its vocabulary packs, with their digests",
         "Bo language",
         "",
         0,
         0,
         with({vocab_option, memory_option, hash_option, language_option}),
         cmd_bo_vocab_list,
         "Bo's words are in its core, which every source reads (kinds of things, actions such\n"
         "as transfer and cancel, conditions, time, units, currencies, types, common fields,\n"
         "states, and roles), or in one of the official vocabulary packs, each a field's words\n"
         "with the standard terms of its built-in actions: finance, commerce, and services. A\n"
         "source uses a pack by a line at its top (use finance; in Chinese 使用 finance: pack\n"
         "ids stay as written). A word of a pack the source does not use is an error, never a\n"
         "name of the contract's own (Bo never guesses). Unlike a language pack, a vocabulary\n"
         "pack changes what runs, so a deploy records each one it uses: its id, version, and\n"
         "the digest of its canonical CBOR (under --hash).\n\n"
         "Packs of your own, given with --vocab (a .vocab file, or a directory's), come after\n"
         "the official ones (bo vocab check FILE checks one).\n\n"
         "Each line: the pack's id, version, name in --language, its words, its built-in\n"
         "actions, and its digest (yours, for a pack of your own). With --json: the same for\n"
         "each, the core first.\n\n"
         "  bo vocab list\n"
         "  bo vocab list --vocab events.vocab\n"
         "  bo vocab list --language zh-Hant-HK --hash sm3 "
         "--json\n\n" CEXCHAIN_BO_PACKS_HELP},
        {{"vocab", "show"},
         "Show the core or a vocabulary pack: its words, their categories, and its actions",
         "Bo language",
         "PACK|FILE",
         1,
         1,
         with({vocab_option, hash_option, language_option}),
         cmd_bo_vocab_show,
         "PACK is core or a vocabulary pack's id (bo vocab list shows them; a pack of your own\n"
         "given with --vocab), or FILE a vocabulary pack file of your own. Prints each word:\n"
         "its category, its concept id, its spelling in --language, and for a field the type\n"
         "its pack gives it (R1), and whether the standard terms may add it to an instance\n"
         "(added, R20) and whether a counterparty an action puts into it consents (taking,\n"
         "R31); then the built-in actions whose standard terms it brings (bo stdlib show\n"
         "ACTION prints each), and the recognition rules only its words reach, which apply\n"
         "only where it is used. With --json: the same, and the pack's canonical CBOR (hex),\n"
         "which its digest covers.\n\n"
         "  bo vocab show core\n"
         "  bo vocab show services --language zh-Hans-CN\n"
         "  bo vocab show commerce --json\n"
         "  bo vocab show events.vocab --language zh-Hant-HK\n\n" CEXCHAIN_BO_PACKS_HELP},
    };
}

} // namespace cexchain::cli
