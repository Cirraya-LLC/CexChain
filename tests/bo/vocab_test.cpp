// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Vocabulary pack files (G6 of D-054): the official ones as the compiler
// carries them, and users' packs: their reader, the checks a pack set makes
// of them, `use`, and the bundle key that carries them (key 7). Front end
// only; rebuilding a deploy that uses one is in build_test.cpp.

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

/// A user's pack, as text: a club's members, with a field the terms add and a
/// counterparty who consents. Each part can be changed before `text()`.
struct TestVocab {
    std::string id = "club";
    std::uint64_t version = 1;
    std::string required;
    std::map<std::string, std::string> concepts{
        {"act.join", R"({"category": "action"})"},
        {"state.joined", R"({"category": "state"})"},
        {"field.member",
         R"({"category": "field", "type": "party", "added": true, "taking": true})"},
        {"unit.dozen", R"({"category": "unit", "dimension": "count", "scale": 12})"}};
    std::vector<std::string> terms{"bo 1", "use club", "can join to counterparty",
                                   "  active -> joined", "  member = counterparty"};
    std::map<std::string, std::map<std::string, std::string>> words{
        {"en",
         {{"act.join", R"({"word": "join", "forms": {"third": "joins"}})"},
          {"state.joined", R"("joined")"},
          {"field.member", R"({"word": "member", "forms": {"object": "the member"}})"},
          {"unit.dozen", R"({"word": "dozen", "forms": {"plural": "dozens"}})"}}},
        {"zh-Hant-HK",
         {{"act.join", R"("入會")"},
          {"state.joined", R"("已入會")"},
          {"field.member", R"("會員")"},
          {"unit.dozen", R"("打")"}}}};
    std::string extra;

    [[nodiscard]] std::string text() const {
        std::string out = "# A club's words.\n{\"format\": 1, \"id\": \"" + id +
                          "\", \"version\": " + std::to_string(version) + ", \"edition\": 1, ";
        if (!required.empty()) {
            out += "\"requires\": [" + required + "], ";
        }
        out += "\"concepts\": {";
        bool first = true;
        for (const auto& [k, v] : concepts) {
            out += (first ? "" : ", ") + std::string("\"") + k + "\": " + v;
            first = false;
        }
        out += "}, ";
        if (!terms.empty()) {
            out += "\"terms\": [";
            first = true;
            for (const std::string& line : terms) {
                out += (first ? "\"" : ", \"") + line + "\"";
                first = false;
            }
            out += "], ";
        }
        out += extra;
        out += "\"languages\": {";
        first = true;
        for (const auto& [language, list] : words) {
            out += (first ? "" : ", ") + std::string("\"") + language +
                   "\": {\"name\": \"club\", " + "\"words\": {";
            bool inner = true;
            for (const auto& [k, v] : list) {
                out += (inner ? "" : ", ") + std::string("\"") + k + "\": " + v;
                inner = false;
            }
            out += "}}";
            first = false;
        }
        out += "}}";
        return out;
    }
};

bool reports(const std::vector<Diagnostic>& diagnostics, std::string_view code,
             std::initializer_list<std::pair<std::string_view, std::string_view>> args = {}) {
    return std::ranges::any_of(diagnostics, [&](const Diagnostic& d) {
        return d.code == code && std::ranges::all_of(args, [&](const auto& arg) {
                   return d.arg(arg.first) == arg.second;
               });
    });
}

std::string all_text(const std::vector<Diagnostic>& diagnostics) {
    std::string out;
    for (const Diagnostic& d : diagnostics) {
        out += std::string(d.code) + ": " + render(d, nullptr) + "\n";
    }
    return out;
}

VocabularyHandle must_read(const TestVocab& v) {
    VocabularyRead read = read_vocabulary_pack(v.text());
    INFO(v.text() << "\n" << all_text(read.diagnostics));
    REQUIRE(read.pack != nullptr);
    return read.pack;
}

void refuses(const TestVocab& v, std::string_view code,
             std::initializer_list<std::pair<std::string_view, std::string_view>> args = {}) {
    const VocabularyRead read = read_vocabulary_pack(v.text());
    INFO(v.text() << "\n" << all_text(read.diagnostics));
    CHECK(read.pack == nullptr);
    CHECK(reports(read.diagnostics, code, args));
}

/// The official packs and these users' packs, which must read together.
PackSet set_with(std::vector<VocabularyHandle> users) {
    PackSetRead read = make_pack_set({}, Officials::current, std::move(users));
    INFO(all_text(read.diagnostics));
    REQUIRE(read.set.has_value());
    return std::move(*read.set);
}

/// The diagnostics of making a set with these users' packs.
std::vector<Diagnostic> set_problems(std::vector<VocabularyHandle> users) {
    return make_pack_set({}, Officials::current, std::move(users)).diagnostics;
}

/// A source checked with a set (lexed, parsed, checked); the codes of every
/// problem, in order.
struct CheckedSource {
    Parsed parsed;
    Checked checked;
    std::vector<Diagnostic> all;
};

CheckedSource check_with(const PackSet& set, std::string_view source) {
    const Lexicon lexicon(set);
    const Lexed lexed = lex(source, lexicon);
    CheckedSource out{parse(source, lexed), {}, lexed.diagnostics};
    out.all.insert(out.all.end(), out.parsed.diagnostics.begin(), out.parsed.diagnostics.end());
    if (!has_errors(out.all)) {
        out.checked = check(source, out.parsed.file);
        out.all.insert(out.all.end(), out.checked.diagnostics.begin(),
                       out.checked.diagnostics.end());
    }
    return out;
}

constexpr std::string_view club_source = "use club\n"
                                         "contract Club\n"
                                         "parties we\n"
                                         "thing Card\n"
                                         "  holder we\n"
                                         "  quantity dozen\n"
                                         "can join\n";

} // namespace

TEST_CASE("the official vocabulary packs are files, their concepts the edition's", "[bo][vocab]") {
    REQUIRE(vocabulary_packs().size() == 3);
    std::size_t words = 0;
    for (const VocabularyPack* pack : vocabulary_packs()) {
        INFO(pack->id);
        CHECK(pack->official());
        CHECK(pack->version == 2);
        CHECK(pack->edition == edition);
        // Each spelled in the three official languages, and named in each.
        CHECK(pack->languages.size() == 3);
        CHECK(vocabulary_name(*pack, official_pack("zh-Hant-HK")) != pack->id);
        for (const Concept* c : pack->concepts) {
            CHECK(c->owner == pack);
            CHECK(find_concept(c->id) == c);
            CHECK(pack_of(*c) == pack->id);
        }
        words += pack->concepts.size();
        // The carried version 1 has the same concepts and terms, and no
        // spellings: the language packs of its release spell them.
        const VocabularyPack* first = find_vocabulary_pack(pack->id, 1);
        REQUIRE(first != nullptr);
        CHECK(first->languages.empty());
        CHECK(first->concepts == pack->concepts);
        CHECK(first->terms == pack->terms);
        CHECK(first->canonical != pack->canonical);
    }
    CHECK(words == 58);
    CHECK(find_vocabulary_pack("finance")->concepts.size() == 24);
    CHECK(find_vocabulary_pack("commerce")->concepts.size() == 22);
    CHECK(find_vocabulary_pack("services")->concepts.size() == 12);
    // The core's words are its own: 81, besides the keywords.
    std::size_t core = 0;
    for (const Concept* c : concepts()) {
        core += c->owner == nullptr && !c->retired && c->category != Category::keyword ? 1 : 0;
    }
    CHECK(core == 84);
    // Each release reads with its own versions.
    CHECK(vocabulary_packs(Officials::current).front()->version == 2);
    CHECK(vocabulary_packs(Officials::before_pack_files).front()->version == 1);
    CHECK(vocabulary_packs(Officials::before_temperature).front()->version == 1);
    CHECK(vocabulary_packs(Officials::before_vocabulary).empty());
    // The official files are users' packs' shape: but a user's pack may not
    // take an official id.
    for (const VocabularyText& text : official_vocabulary_texts()) {
        INFO(text.id << " " << text.version);
        const VocabularyRead read = read_vocabulary_pack(text.text);
        CHECK(read.pack == nullptr);
        CHECK(reports(read.diagnostics, "vocab.official-id"));
    }
}

TEST_CASE("a user's vocabulary pack reads, every word spelled", "[bo][vocab]") {
    const VocabularyHandle pack = must_read(TestVocab{});
    CHECK(pack->id == "club");
    CHECK(!pack->official());
    CHECK(pack->vocab == Vocab::user);
    REQUIRE(pack->concepts.size() == 4);
    const Concept* member = pack->find("club:field.member");
    REQUIRE(member != nullptr);
    CHECK(member->category == Category::field);
    CHECK(member->type == "party");
    CHECK(member->flags == (field_added | field_taking));
    CHECK(member->owner == pack.get());
    CHECK(pack_of(*member) == "club");
    CHECK(wire_name(member, {}) == "member");
    // Its unit: count, twelve of its smallest.
    const Concept* dozen = pack->find("club:unit.dozen");
    REQUIRE(dozen != nullptr);
    const UnitInfo* unit = unit_info(dozen);
    REQUIRE(unit != nullptr);
    CHECK(unit->dimension == model::Dimension::count);
    CHECK(unit->factor == 12);
    CHECK(pack->terms == "bo 1\nuse club\ncan join to counterparty\n  active -> joined\n  member "
                         "= counterparty\n");
    CHECK(vocabulary_name(*pack, nullptr) == "club");
    // Its digest covers its canonical CBOR, not its layout.
    TestVocab spaced;
    const std::string text = spaced.text();
    std::string wide;
    for (const char c : text) {
        wide += c;
        if (c == ',') {
            wide += "\n   ";
        }
    }
    const VocabularyRead again = read_vocabulary_pack(wide);
    REQUIRE(again.pack != nullptr);
    CHECK(again.pack->canonical == pack->canonical);
    // A word's spelling in a language that has it, else English.
    CHECK(concept_word(member, official_pack("zh-Hant-HK"))->spellings.front() == "會員");
    CHECK(concept_word(member, official_pack("zh-Hans-CN"))->spellings.front() == "member");
}

TEST_CASE("a user's vocabulary pack is refused for each problem, with its code", "[bo][vocab]") {
    SECTION("shape and ids") {
        TestVocab v;
        v.id = "Club";
        refuses(v, "vocab.bad-id");
        v.id = "finance";
        refuses(v, "vocab.official-id", {{"value", "finance"}});
        v.id = "core";
        refuses(v, "vocab.official-id");
        CHECK(reports(read_vocabulary_pack("{").diagnostics, "vocab.syntax"));
        CHECK(reports(read_vocabulary_pack(R"({"format": 2, "edition": 1})").diagnostics,
                      "vocab.format"));
        CHECK(reports(read_vocabulary_pack(std::string(max_vocab_size + 1, ' ')).diagnostics,
                      "vocab.too-large"));
        TestVocab extra;
        extra.extra = R"("colour": "blue", )";
        refuses(extra, "pack.unknown-key");
        TestVocab self;
        self.required = R"("club")";
        refuses(self, "vocab.bad-requires");
    }
    SECTION("concepts") {
        TestVocab v;
        v.concepts["act.Join!"] = R"({"category": "action"})";
        refuses(v, "vocab.bad-concept");
        TestVocab kind;
        kind.concepts["kind.club"] = R"({"category": "kind"})";
        refuses(kind, "vocab.category", {{"category", "kind"}});
        TestVocab mismatch;
        mismatch.concepts["act.join"] = R"({"category": "state"})";
        refuses(mismatch, "pack.wrong-category");
        TestVocab argument;
        argument.concepts["act.join"] = R"({"category": "action", "argument": true})";
        refuses(argument, "vocab.argument");
        TestVocab no;
        no.concepts["act.join"] = R"({"category": "action", "argument": false})";
        refuses(no, "pack.bad-value");
        TestVocab type;
        type.concepts["field.member"] = R"({"category": "field", "type": "portion"})";
        refuses(type, "vocab.type", {{"value", "portion"}});
        TestVocab untyped;
        untyped.concepts["field.member"] = R"({"category": "field"})";
        refuses(untyped, "pack.missing-key", {{"key", "type"}});
        TestVocab flag;
        flag.concepts["field.member"] = R"({"category": "field", "type": "text", "added": true})";
        refuses(flag, "vocab.flag");
        TestVocab unit;
        unit.concepts["unit.dozen"] = R"({"category": "unit", "dimension": "volume", "scale": 1})";
        refuses(unit, "vocab.unit");
        unit.concepts["unit.dozen"] = R"({"category": "unit", "dimension": "count", "scale": 0})";
        refuses(unit, "vocab.unit");
    }
    SECTION("names of the core's and official words") {
        // The plain name of a core word (holder) or an official one
        // (pledge), in the same category.
        TestVocab holder;
        holder.concepts["field.holder"] = R"({"category": "field", "type": "party"})";
        holder.words["en"]["field.holder"] = R"("keeper of the card")";
        holder.words["zh-Hant-HK"]["field.holder"] = R"("持卡人")";
        refuses(holder, "vocab.shadows", {{"concept", "field.holder"}});
        TestVocab pledge;
        pledge.concepts["act.pledge"] = R"({"category": "action"})";
        pledge.words["en"]["act.pledge"] = R"("pawn")";
        pledge.words["zh-Hant-HK"]["act.pledge"] = R"("典當")";
        refuses(pledge, "vocab.shadows", {{"other", "act.pledge"}});
    }
    SECTION("terms and spellings") {
        TestVocab terms;
        terms.terms = {"bo 1\\ncan join"};
        refuses(terms, "vocab.bad-terms");
        TestVocab unspelled;
        unspelled.words["zh-Hant-HK"].erase("act.join");
        refuses(unspelled, "vocab.unspelled",
                {{"language", "zh-Hant-HK"}, {"concept", "club:act.join"}});
        TestVocab stranger;
        stranger.words["en"]["act.leave"] = R"("leave")";
        refuses(stranger, "vocab.not-own");
        TestVocab twice;
        twice.words["en"]["state.joined"] = R"("join")";
        refuses(twice, "vocab.duplicate-spelling", {{"spelling", "join"}});
        TestVocab holed;
        holed.words["en"]["act.join"] = R"("join …")";
        refuses(holed, "pack.unexpected-hole");
        TestVocab language;
        language.words["en x"] = language.words["en"];
        refuses(language, "vocab.bad-language");
        TestVocab none;
        none.words.clear();
        refuses(none, "pack.too-many");
    }
}

TEST_CASE("a pack set checks users' packs against the others", "[bo][vocab]") {
    // A spelling Bo already has.
    TestVocab clash;
    clash.words["en"]["act.join"] = R"("transfer")";
    CHECK(reports(set_problems({must_read(clash)}), "vocab.conflict",
                  {{"pack", "club"}, {"spelling", "transfer"}}));
    // Two packs with one id; a required pack not given; a cycle.
    CHECK(reports(set_problems({must_read(TestVocab{}), must_read(TestVocab{})}),
                  "vocab.duplicate-id"));
    TestVocab needs;
    needs.required = R"("other")";
    CHECK(reports(set_problems({must_read(needs)}), "vocab.unknown-requires",
                  {{"pack", "club"}, {"other", "other"}}));
    TestVocab a;
    a.id = "alpha";
    a.required = R"("beta")";
    a.terms.clear();
    a.concepts = {{"state.open", R"({"category": "state"})"}};
    a.words = {{"en", {{"state.open", R"("open")"}}}};
    TestVocab b = a;
    b.id = "beta";
    b.required = R"("alpha")";
    b.concepts = {{"state.shut", R"({"category": "state"})"}};
    b.words = {{"en", {{"state.shut", R"("shut")"}}}};
    CHECK(reports(set_problems({must_read(a), must_read(b)}), "vocab.cycle"));
    // A language no pack of the set has: a warning.
    TestVocab french;
    french.words["fr"] = french.words["en"];
    french.words["fr"]["act.join"] = R"("adhérer")";
    french.words["fr"]["state.joined"] = R"("adhéré")";
    french.words["fr"]["field.member"] = R"("membre")";
    french.words["fr"]["unit.dozen"] = R"("douzaine")";
    const PackSetRead with_french =
        make_pack_set({}, Officials::current, std::vector{must_read(french)});
    CHECK(with_french.set.has_value());
    CHECK(reports(with_french.diagnostics, "vocab.no-language", {{"language", "fr"}}));
    // Terms that do not read, use a pack they may not, or hold something
    // other than the terms of the pack's actions.
    TestVocab bad;
    bad.terms = {"bo 1", "use club", "can join to", "  active -> joined"};
    CHECK(reports(set_problems({must_read(bad)}), "vocab.terms", {{"line", "3"}}));
    TestVocab other_pack;
    other_pack.terms = {"bo 1", "use club", "use finance", "can join", "  active -> pledged"};
    CHECK(reports(set_problems({must_read(other_pack)}), "vocab.terms",
                  {{"code", "check.unknown-pack"}}));
    TestVocab unused;
    unused.terms = {"bo 1", "use club", "can join", "  active -> pledged"};
    CHECK(reports(set_problems({must_read(unused)}), "vocab.terms",
                  {{"code", "check.pack-not-used"}}));
    TestVocab core_action;
    core_action.terms = {"bo 1", "use club", "can transfer", "  active -> joined"};
    CHECK(reports(set_problems({must_read(core_action)}), "vocab.terms-clause", {{"line", "3"}}));
    // With finance required, its words may be used.
    TestVocab finance;
    finance.required = R"("finance")";
    finance.terms = {"bo 1", "use club", "use finance", "can join", "  active -> pledged"};
    CHECK(!has_errors(set_problems({must_read(finance)})));
}

TEST_CASE("a source uses a user's pack: its words, its terms, its rules", "[bo][vocab]") {
    const PackSet set = set_with({must_read(TestVocab{})});
    REQUIRE(set.vocabularies().find("club") != nullptr);
    REQUIRE(set.vocabularies().terms != nullptr);
    CHECK(set.vocabularies().terms->templates.size() == 1);
    const CheckedSource ok = check_with(set, club_source);
    INFO(all_text(ok.all));
    CHECK(!has_errors(ok.all));
    const model::Model& m = ok.checked.model;
    CHECK(m.packs == std::vector<std::string>{"club"});
    REQUIRE(m.vocabularies.size() == 1);
    CHECK(m.vocabularies[0] == set.vocabularies().find("club"));
    // The terms' field is added (R20), its counterparty consents (R31).
    const auto member = std::ranges::find_if(m.fields, [](const model::Field& f) {
        return f.word != nullptr && f.word->id == "club:field.member";
    });
    REQUIRE(member != m.fields.end());
    CHECK(member->rule == "R20");
    REQUIRE(m.actions.size() == 1);
    CHECK(m.actions[0].terms);
    // In Chinese, the same model.
    const CheckedSource zh =
        check_with(set, "使用 club\n合約 Club\n訂約方 我方\n物件 Card\n  持有人 "
                        "我方\n  數量 打\n可入會\n");
    INFO(all_text(zh.all));
    CHECK(!has_errors(zh.all));
    CHECK(dump(zh.checked.model) == dump(m));
    // Its words without `use`, or `use` without the pack given.
    const CheckedSource unused =
        check_with(set, "contract Club\nparties we\nthing Card\n  holder we\ncan join\n");
    CHECK(reports(unused.all, "check.pack-not-used", {{"pack", "club"}}));
    const CheckedSource unknown = check_with(set_with({}), "use club\ncontract Club\n");
    CHECK(reports(unknown.all, "check.unknown-pack"));
    // A pack that requires another needs its `use` too.
    TestVocab needs;
    needs.required = R"("finance")";
    const PackSet with_needs = set_with({must_read(needs)});
    CHECK(reports(check_with(with_needs, club_source).all, "check.pack-requires",
                  {{"pack", "club"}, {"other", "finance"}}));
    const std::string both = "use finance\n" + std::string(club_source);
    CHECK(!has_errors(check_with(with_needs, both).all));
    // Messages and the contract text spell the pack's words in the
    // reader's language, as the set holds them.
    TestVocab declared;
    declared.concepts["field.member"] = R"({"category": "field", "type": "party", "taking": true})";
    const PackSet with_declared = set_with({must_read(declared)});
    const CheckedSource missing = check_with(with_declared, club_source);
    const auto standard =
        std::ranges::find(missing.all, std::string_view("check.standard-field"), &Diagnostic::code);
    REQUIRE(standard != missing.all.end());
    const std::string message = render(*standard, with_declared.find("zh-Hant-HK"));
    CHECK(message.find("入會") != std::string::npos);
    CHECK(message.find("會員") != std::string::npos);
    CHECK(render(*standard, nullptr).find("join") != std::string::npos);
    const Explained text = explain(m, set.find("zh-Hant-HK"));
    CHECK(text.packs.find("club") != std::string::npos);
    std::string clauses;
    for (const ExplainedSection& section : text.sections) {
        for (const ExplainedClause& c : section.clauses) {
            clauses += c.text + "\n";
        }
    }
    CHECK(clauses.find("會員") != std::string::npos);
}

TEST_CASE("a bundle embeds a user's pack whole (key 7), and opens with it", "[bo][vocab]") {
    const PackSet set = set_with({must_read(TestVocab{})});
    const auto made = make_source_bundle(club_source, 1, set, provider(), crypto::HashAlg::sha256);
    REQUIRE(made.has_value());
    const SourceBundle& bundle = *made;
    REQUIRE(bundle.vocabulary.size() == 1);
    CHECK(bundle.vocabulary[0].id == "club");
    CHECK(bundle.vocabulary[0].version == 1);
    REQUIRE(bundle.embedded_vocabulary.size() == 1);
    // {1, 2, 3, 4, 6, 7}: key 7 holds the pack's canonical CBOR.
    const auto encoded = encode_source_bundle(bundle);
    REQUIRE(encoded.has_value());
    const auto value = cbor::decode(*encoded);
    REQUIRE(value.has_value());
    CHECK(value->as_map()->size() == 6);
    REQUIRE(value->find(7) != nullptr);
    CHECK(*cbor::encode(value->find(7)->as_array()->front()) ==
          set.vocabularies().find("club")->canonical);
    const auto decoded = decode_source_bundle(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == bundle);
    // It opens without the pack at hand: the bundle carries it.
    const OpenedSource opened = open_source_bundle(bundle, provider(), crypto::HashAlg::sha256);
    INFO(opened.detail);
    CHECK(opened.problem == OpenProblem::none);
    REQUIRE(opened.packs.has_value());
    REQUIRE(opened.packs->vocabularies().find("club") != nullptr);
    CHECK(!has_errors(check_with(*opened.packs, club_source).all));

    SECTION("the embedded pack changed") {
        SourceBundle changed = bundle;
        TestVocab other;
        other.words["en"]["state.joined"] = R"("enrolled")";
        changed.embedded_vocabulary[0] = *cbor::decode(must_read(other)->canonical);
        const OpenedSource o = open_source_bundle(changed, provider(), crypto::HashAlg::sha256);
        CHECK(o.problem == OpenProblem::embedded);
        CHECK(o.detail.find("the embedded vocabulary pack club") != std::string::npos);
    }
    SECTION("named but not embedded, or embedded but not named") {
        SourceBundle missing = bundle;
        missing.embedded_vocabulary.clear();
        const OpenedSource a = open_source_bundle(missing, provider(), crypto::HashAlg::sha256);
        CHECK(a.problem == OpenProblem::unknown_official);
        CHECK(a.detail.find("club version 1, which is neither in the bundle") != std::string::npos);
        SourceBundle extra = bundle;
        TestVocab second;
        second.id = "second";
        second.terms = {"bo 1", "use second", "can join", "  active -> joined"};
        extra.embedded_vocabulary.push_back(*cbor::decode(must_read(second)->canonical));
        CHECK(open_source_bundle(extra, provider(), crypto::HashAlg::sha256).problem ==
              OpenProblem::embedded);
    }
    SECTION("an embedded pack that does not read") {
        SourceBundle broken = bundle;
        broken.embedded_vocabulary[0] =
            cbor::Value::map({{cbor::Value::text("id"), cbor::Value::text("club")}});
        const OpenedSource o = open_source_bundle(broken, provider(), crypto::HashAlg::sha256);
        CHECK(o.problem == OpenProblem::embedded);
        CHECK(o.detail.find("does not read") != std::string::npos);
    }
    SECTION("with the official packs of an earlier release") {
        PackSetRead earlier = make_pack_set({}, Officials::before_pack_files);
        REQUIRE(earlier.set.has_value());
        SourceBundle old = bundle;
        const SourceBundle earlier_refs = *make_source_bundle("contract C\n", 1, *earlier.set,
                                                              provider(), crypto::HashAlg::sha256);
        old.packs = earlier_refs.packs;
        const OpenedSource o = open_source_bundle(old, provider(), crypto::HashAlg::sha256);
        CHECK(o.problem == OpenProblem::conflict);
    }
    SECTION("decoding refuses key 7 that is not a list of maps, and more than key 6 names") {
        cbor::Map map = *value->as_map();
        for (cbor::MapEntry& e : map) {
            if (e.key.as_int64() == 7) {
                e.value = cbor::Value::array({cbor::Value::text("club")});
            }
        }
        CHECK(!decode_source_bundle(*cbor::encode(cbor::Value::map(map))).has_value());
        SourceBundle twice = bundle;
        twice.embedded_vocabulary.push_back(twice.embedded_vocabulary[0]);
        CHECK(!encode_source_bundle(twice).has_value());
    }
}
