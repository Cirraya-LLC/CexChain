// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Language packs (milestone 1 of the Bo compiler): the official packs, their
// digests, and every rule a pack must keep. Set CEXCHAIN_UPDATE_GOLDENS=1 to
// rewrite tests/bo/golden/pack-digests.txt after a deliberate change.

#include <algorithm>
#include <cstdlib>
#include <format>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const std::string golden_digests = std::string(CEXCHAIN_BO_GOLDEN_DIR) + "/pack-digests.txt";

/// A word for a concept that no official pack uses: "q" and the id's
/// letters ("kw.can" gives "qcan").
std::string q_word(std::string_view id) {
    std::string out = "q";
    for (const char c : id.substr(id.find('.') + 1)) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            out.push_back(c);
        }
    }
    return out;
}

struct TestPack {
    std::string id = "test";
    std::string top;        ///< more top-level entries, each ending in ","
    std::string reading;    ///< more reading rules, each ending in ","
    std::string vocabulary; ///< vocabulary entries, comma-separated
    std::set<std::string> skip_keywords;

    [[nodiscard]] std::string text() const {
        std::string keywords;
        for (const Concept* c_entry : concepts()) {
            const Concept& c = *c_entry;
            if (c.category != Category::keyword || skip_keywords.contains(std::string(c.id))) {
                continue;
            }
            keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + std::string(c.id) +
                        "\": \"" + q_word(c.id) + "\"";
        }
        return "{" + top + R"("format": 1, "id": ")" + id +
               R"(", "version": 1, "language": "qaa", "name": "Test", "official": false, )"
               R"("edition": 1, "reading": {)" +
               reading + R"("separation": "spaces"}, "keywords": {)" + keywords +
               "}, \"vocabulary\": {" + vocabulary + "}}";
    }
};

PackRead read(const TestPack& pack) {
    return read_pack(pack.text());
}

Pack must_read(const TestPack& pack) {
    PackRead r = read(pack);
    for (const Diagnostic& d : r.diagnostics) {
        INFO(render(d, nullptr));
        CHECK(d.severity() == Severity::warning);
    }
    REQUIRE(r.pack);
    return *r.pack;
}

/// True if one of the diagnostics has this code and these arguments.
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
        out += render(d, nullptr) + "\n";
    }
    return out;
}

/// Reads a test pack expecting it to fail with `code`.
void refuses(const TestPack& pack, std::string_view code,
             std::initializer_list<std::pair<std::string_view, std::string_view>> args = {}) {
    const PackRead r = read(pack);
    INFO(pack.text());
    INFO(all_text(r.diagnostics));
    CHECK_FALSE(r.pack);
    CHECK(reports(r.diagnostics, code, args));
}

std::string digest_hex(const Pack& pack, crypto::HashAlg alg) {
    const crypto::openssl::Provider provider;
    const auto d = digest(pack, provider, alg);
    REQUIRE(d);
    return to_hex(d->bytes());
}

} // namespace

TEST_CASE("the official packs read, and their digests match the goldens", "[bo][packs]") {
    REQUIRE(official_packs().size() == 3);
    std::string lines;
    for (const PackText& text : official_pack_texts()) {
        const PackRead r = read_pack(text.text);
        INFO(text.id << "\n" << all_text(r.diagnostics));
        // Complete: no warning either (every word spelled).
        CHECK(r.diagnostics.empty());
        REQUIRE(r.pack);
        CHECK(r.pack->id == text.id);
        CHECK(r.pack->official);
        CHECK(r.pack->edition == edition);
        lines += std::format("{} {} SHA-256 {}\n", r.pack->id, r.pack->version,
                             digest_hex(*r.pack, crypto::HashAlg::sha256));
        lines += std::format("{} {} SM3 {}\n", r.pack->id, r.pack->version,
                             digest_hex(*r.pack, crypto::HashAlg::sm3));
    }
    // The earlier releases, which the compiler carries so that their
    // deploys rebuild: unchanged, so their digests are those deploys
    // recorded. Version 1 (from before vocabulary packs) lacks the core's
    // kind word thing, and spells the retired kind.record; version 2 lacks
    // the words added since (a temperature).
    for (const auto& [which, version] :
         {std::pair{Officials::before_billing, 5U}, std::pair{Officials::before_requests, 4U},
          std::pair{Officials::before_pack_files, 3U}, std::pair{Officials::before_temperature, 2U},
          std::pair{Officials::before_vocabulary, 1U}}) {
        REQUIRE(official_pack_texts(which).size() == 3);
        REQUIRE(official_packs(which).size() == 3);
        for (const PackText& text : official_pack_texts(which)) {
            const PackRead r = read_pack(text.text);
            INFO(text.id << " " << version << "\n" << all_text(r.diagnostics));
            REQUIRE(r.pack);
            CHECK(r.pack->id == text.id);
            CHECK(r.pack->version == version);
            CHECK(r.pack->official);
            std::size_t missing = 0;
            // Words of the core (the official vocabulary packs' words
            // these versions spell too are not counted).
            for (const Concept& c : core_concepts()) {
                missing +=
                    !c.retired && c.category != Category::keyword && r.pack->word(c.id) == nullptr
                        ? 1U
                        : 0U;
            }
            if (missing == 0) {
                CHECK(r.diagnostics.empty());
            } else {
                REQUIRE(r.diagnostics.size() == 1);
                CHECK(
                    reports(r.diagnostics, "pack.partial", {{"missing", std::to_string(missing)}}));
            }
            CHECK((r.pack->word("kind.record") != nullptr) == (version == 1));
            CHECK((r.pack->word("kind.thing") == nullptr) == (version == 1));
            Officials found = Officials::current;
            CHECK(official_pack(text.id, version, &found) != nullptr);
            CHECK(found == which);
            lines += std::format("{} {} SHA-256 {}\n", r.pack->id, r.pack->version,
                                 digest_hex(*r.pack, crypto::HashAlg::sha256));
            lines += std::format("{} {} SM3 {}\n", r.pack->id, r.pack->version,
                                 digest_hex(*r.pack, crypto::HashAlg::sm3));
        }
    }
    CHECK(official_releases().size() == 6);
    CHECK(official_releases().front() == Officials::current);
    // The official vocabulary packs (vocab.hpp), current and carried.
    const crypto::openssl::Provider provider;
    for (const VocabularyText& text : official_vocabulary_texts()) {
        const VocabularyPack* found = find_vocabulary_pack(text.id, text.version);
        REQUIRE(found != nullptr);
        const VocabularyPack& pack = *found;
        for (const auto& [alg, name] : {std::pair{crypto::HashAlg::sha256, "SHA-256"},
                                        std::pair{crypto::HashAlg::sm3, "SM3"}}) {
            const auto d = digest(pack, provider, alg);
            REQUIRE(d);
            lines += std::format("{} {} {} {}\n", pack.id, pack.version, name, to_hex(d->bytes()));
        }
    }
    if (std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr) {
        std::ofstream(golden_digests) << lines;
    }
    std::ifstream in(golden_digests);
    std::stringstream expected;
    expected << in.rdbuf();
    CHECK(lines == expected.str());
}

/// The words of the official vocabulary packs (their current versions).
static std::size_t vocabulary_words() {
    std::size_t n = 0;
    for (const VocabularyPack* pack : vocabulary_packs()) {
        n += pack->concepts.size();
    }
    return n;
}

TEST_CASE("the official packs spell every keyword, word, message, and sentence", "[bo][packs]") {
    for (const Pack& pack : official_packs()) {
        INFO(pack.id);
        CHECK(pack.version == 6);
        // Every concept but the retired ones, which only the earlier
        // official packs spell: the core's from the pack's file, the
        // official vocabulary packs' from theirs (vocab.hpp).
        for (const Concept* c_entry : concepts()) {
            const Concept& c = *c_entry;
            INFO(c.id);
            CHECK((pack.word(c.id) != nullptr) == !c.retired);
        }
        // The pack's own file spells the core's words alone (G6).
        for (const PackText& text : official_pack_texts()) {
            if (text.id != pack.id) {
                continue;
            }
            const PackRead file = read_pack(text.text);
            REQUIRE(file.pack);
            for (const auto& [id, word] : file.pack->vocabulary) {
                INFO(id);
                CHECK(find_core_concept(id) != nullptr);
            }
            CHECK(file.pack->vocabulary.size() + vocabulary_words() == pack.vocabulary.size());
        }
        for (const MessageSpec& m : message_specs()) {
            INFO(m.code);
            CHECK(pack.messages.contains(m.code));
        }
        for (const SentenceSpec& s : sentence_specs()) {
            INFO(s.id);
            CHECK(pack.sentences.contains(s.id) == !s.retired);
        }
    }
    CHECK(keyword_count() == 22);
    CHECK(english_pack().id == "en");
    CHECK(official_pack("zh-Hant-HK")->name == "繁體中文（香港）");
    CHECK(official_pack("zh-Hans-CN")->keywords.at("kw.each").spellings.front() == "逐个");
}

TEST_CASE("the official packs read together, every spelling with one meaning", "[bo][packs]") {
    const PackSetRead r = make_pack_set({});
    INFO(all_text(r.diagnostics));
    REQUIRE(r.set);
    CHECK(r.diagnostics.empty());
    const PackSet& set = *r.set;
    CHECK(set.packs().size() == 3);
    const auto concept_of = [&](std::string_view spelling) -> std::string {
        const Meaning* m = set.lookup(spelling);
        if (m == nullptr || m->kind != MeaningKind::word) {
            return "";
        }
        return std::string(m->concept_entry->id);
    };
    // The same concepts in every language, and mixed.
    CHECK(concept_of("can") == "kw.can");
    CHECK(concept_of("可") == "kw.can");
    CHECK(concept_of("pledge") == "act.pledge");
    CHECK(concept_of("質押") == "act.pledge");
    CHECK(concept_of("质押") == "act.pledge");
    CHECK(concept_of("pays") == "act.pay");
    CHECK(set.lookup("pays")->form == "third");
    CHECK(concept_of("us") == "role.we");
    CHECK(concept_of("經 … 同意") == "cond.consent_of");
    CHECK(concept_of("consent of …") == "cond.consent_of");
    CHECK(concept_of("… 內") == "cond.within");
    CHECK(concept_of("AI 代理") == "actor.ai_agent");
    CHECK(concept_of("AI代理") == "actor.ai_agent");
    CHECK(concept_of("AI agent") == "actor.ai_agent");
    CHECK(concept_of("GB") == "unit.GB");
    CHECK(concept_of("港元") == "cur.HKD");
    CHECK(concept_of("逐个") == "kw.each");
    // 每个 would be both "each" and 每 + 个 ("per item"): it is neither.
    CHECK(set.lookup("每个") == nullptr);
    CHECK(set.lookup("萬")->multiplier == 10000);
    CHECK(set.lookup("亿")->multiplier == 100000000);
    CHECK(set.lookup("，")->punctuation == ',');
    CHECK(set.lookup("\u3000")->punctuation == ' ');
    CHECK(set.lookup("７")->punctuation == '7');
    CHECK(set.lookup("可用率") == nullptr);
    CHECK(find_language(set.packs(), "zh-Hant")->id == "zh-Hant-HK");
    CHECK(find_language(set.packs(), "zh-hans-cn")->id == "zh-Hans-CN");
    CHECK(find_language(set.packs(), "en")->id == "en");
    CHECK(find_language(set.packs(), "zh") == nullptr); // two packs match
    CHECK(find_language(set.packs(), "fr") == nullptr);
}

TEST_CASE("a pack's digest covers its canonical CBOR, not its layout", "[bo][packs]") {
    const Pack& en = english_pack();
    // The same value written another way: no comments, other spacing, keys in
    // canonical order.
    const auto value = cbor::decode(en.canonical);
    REQUIRE(value);
    const PackRead again = read_pack(cbor::diagnostic(*value));
    REQUIRE(again.pack);
    CHECK(again.pack->canonical == en.canonical);
    // And given as CBOR, as a source bundle carries it.
    const PackRead from_cbor = read_pack(*value);
    REQUIRE(from_cbor.pack);
    CHECK(digest_hex(*from_cbor.pack, crypto::HashAlg::sha256) ==
          digest_hex(en, crypto::HashAlg::sha256));
    // Any change of content changes it.
    TestPack a;
    TestPack b;
    b.vocabulary = R"("act.pay": "qpayx")";
    CHECK(must_read(a).canonical != must_read(b).canonical);
}

TEST_CASE("a pack that misses a keyword is refused", "[bo][packs]") {
    TestPack pack;
    pack.skip_keywords = {"kw.use"};
    refuses(pack, "pack.missing-keyword", {{"pack", "test"}, {"concept", "kw.use"}});
    // Vocabulary may be partial: a warning, and English fills in. The words
    // counted are the core's (the vocabulary packs spell their own).
    const PackRead partial = read(TestPack{});
    REQUIRE(partial.pack);
    CHECK(reports(partial.diagnostics, "pack.partial", {{"missing", "84"}, {"total", "84"}}));
}

TEST_CASE("one spelling with two meanings is refused, within a pack and across packs",
          "[bo][packs]") {
    // Within one pack.
    TestPack twice;
    twice.vocabulary = R"("act.pledge": "lodge", "act.transfer": "lodge")";
    refuses(twice, "pack.duplicate-spelling", {{"pack", "test"}, {"spelling", "lodge"}});

    // Across two packs given together.
    TestPack a;
    a.id = "company-a";
    a.vocabulary = R"("act.pledge": "lodge")";
    TestPack b;
    b.id = "company-b";
    b.vocabulary = R"("act.transfer": "lodge")";
    // The two test packs spell the keywords alike, which is fine: same meaning.
    PackSetRead r = make_pack_set({must_read(a), must_read(b)});
    INFO(all_text(r.diagnostics));
    CHECK_FALSE(r.set);
    CHECK(reports(r.diagnostics, "pack.conflict",
                  {{"spelling", "lodge"},
                   {"pack", "company-a"},
                   {"meaning", "act.pledge"},
                   {"other_pack", "company-b"},
                   {"other", "act.transfer"}}));
    CHECK(render(r.diagnostics.front(), official_pack("zh-Hant-HK")) ==
          "lodge 在語言包 company-a 中解作 act.pledge，在語言包 company-b 中卻解作 "
          "act.transfer；同一拼寫不可有兩個意思");

    // Against an official pack.
    TestPack c;
    c.vocabulary = R"("act.transfer": "pledge")";
    r = make_pack_set({must_read(c)});
    CHECK_FALSE(r.set);
    CHECK(reports(r.diagnostics, "pack.conflict",
                  {{"spelling", "pledge"}, {"pack", "en"}, {"other", "act.transfer"}}));

    // The same meaning again is no conflict: a company's own word for pledge,
    // beside the official ones.
    TestPack d;
    d.vocabulary = R"("act.pledge": ["抵押", "質押"])";
    r = make_pack_set({must_read(d)});
    INFO(all_text(r.diagnostics));
    REQUIRE(r.set);
    CHECK(r.set->lookup("抵押")->concept_entry->id == "act.pledge");
    CHECK(r.set->lookup("qcan")->pack == "test");
}

TEST_CASE("a word an attaching rule could split is refused", "[bo][packs]") {
    // Within a pack: "pqkq" is daily, and also "pq" (per) + "kq" (kg).
    TestPack pack;
    pack.reading = R"("attach": [{"word": "price.per", "before": ["unit"]}], )";
    pack.vocabulary = R"("price.per": "pq", "unit.kg": "kq", "time.daily": "pqkq")";
    refuses(pack, "pack.ambiguous-attachment",
            {{"spelling", "pqkq"}, {"meaning", "time.daily"}, {"first", "pq"}, {"second", "kq"}});
    // Narrowing the rule settles it.
    pack.reading = R"("attach": [{"word": "price.per", "before": ["currency"]}], )";
    must_read(pack);

    // Across packs: the draft's 每个 for "each" against zh-Hans-CN's 每 + 个.
    TestPack each;
    each.id = "draft";
    each.skip_keywords = {"kw.each"};
    std::string text = each.text();
    text.replace(text.find("\"keywords\": {") + 13, 0, "\"kw.each\": \"每个\", ");
    const PackRead read_each = read_pack(text);
    INFO(all_text(read_each.diagnostics));
    REQUIRE(read_each.pack); // alone it is fine
    const PackSetRead r = make_pack_set({*read_each.pack});
    CHECK_FALSE(r.set);
    CHECK(
        reports(r.diagnostics, "pack.ambiguous-attachment",
                {{"spelling", "每个"}, {"meaning", "kw.each"}, {"first", "每"}, {"second", "个"}}));

    // After a word: "… 內" attaches to the time word before it.
    TestPack after;
    after.reading = R"("attach": [{"word": "cond.within", "after": ["time"]}], )";
    after.vocabulary = R"("cond.within": "… nq", "time.day": "dq", "time.daily": "dqnq")";
    refuses(after, "pack.ambiguous-attachment",
            {{"spelling", "dqnq"}, {"first", "dq"}, {"second", "nq"}});
}

TEST_CASE("spellings are exact words", "[bo][packs]") {
    const auto bad =
        [](std::string vocabulary, std::string_view code,
           std::initializer_list<std::pair<std::string_view, std::string_view>> args = {}) {
            TestPack pack;
            pack.vocabulary = std::move(vocabulary);
            refuses(pack, code, args);
        };
    // Invisible and compatibility characters: two words that look alike are
    // never different words.
    bad(R"("act.pledge": "質\u200b押")", "pack.bad-character", {{"character", "U+200B"}});
    // U+F900 looks like U+8C48, and NFKC folds it into that.
    bad(R"("act.pledge": "\uf900")", "pack.bad-character", {{"character", "U+F900 (\uF900)"}});
    bad(R"("unit.GB": "ＧＢ")", "pack.bad-character", {{"character", "U+FF27 (Ｇ)"}});
    bad(R"("act.pledge": "a-b")", "pack.bad-character", {{"character", "U+002D (-)"}});
    bad(R"("act.pledge": "質，押")", "pack.bad-character");
    bad(R"("act.pledge": "a\u00a0b")", "pack.bad-character", {{"character", "U+00A0"}});
    // Shape.
    bad(R"("act.pledge": "2x")", "pack.bad-spelling");
    bad(R"("act.pledge": "a  b")", "pack.bad-spelling");
    bad(R"("act.pledge": " a")", "pack.bad-spelling");
    bad(R"("act.pledge": "")", "pack.bad-spelling");
    bad(R"("act.pledge": "a b c d e")", "pack.bad-spelling");
    bad(R"("act.pledge": [])", "pack.expected-text");
    bad(R"("act.pledge": 7)", "pack.expected-text");
    // The argument's place, exactly where a concept takes one.
    bad(R"("cond.over": "overq")", "pack.needs-hole", {{"concept", "cond.over"}});
    bad(R"("cond.over": "… a …")", "pack.needs-hole");
    bad(R"("act.pay": "pay …")", "pack.unexpected-hole", {{"concept", "act.pay"}});
    bad(R"("act.pay": "…")", "pack.bad-spelling");
    // Forms.
    bad(R"("act.pay": {"word": "payq", "forms": {"Third": "paysq"}})", "pack.bad-form");
    bad(R"("act.pay": {"forms": {"third": "paysq"}})", "pack.missing-key", {{"key", "word"}});
    bad(R"("act.pay": {"word": "payq", "plural": "x"})", "pack.unknown-key");
    // Concepts.
    bad(R"("act.fly": "fly")", "pack.unknown-concept", {{"concept", "act.fly"}});
    // A retired concept: only the earlier official packs spell it.
    bad(R"("kind.record": "record")", "pack.unknown-concept", {{"concept", "kind.record"}});
    bad(R"("kw.can": "canq")", "pack.wrong-category", {{"category", "keyword"}});

    // What is allowed: letters of any script, marks, digits after the first.
    TestPack fine;
    fine.vocabulary =
        R"("act.pledge": ["Pfand", "залог", "จำนำ", "質押x2", "cafe\u0301"],)"
        R"("cond.over": "… über", "act.pay": {"word": "payq", "forms": {"third": "paysq"}})";
    const Pack pack = must_read(fine);
    CHECK(pack.vocabulary.at("act.pledge").spellings.size() == 5);
}

TEST_CASE("a pack's shape is checked, every problem reported", "[bo][packs]") {
    CHECK(reports(read_pack("[1, 2]").diagnostics, "pack.expected-map", {{"path", "."}}));
    CHECK(reports(read_pack("{1: 2").diagnostics, "pack.syntax"));
    CHECK(reports(read_pack(std::string(max_pack_size + 1, ' ')).diagnostics, "pack.too-large"));

    TestPack pack;
    pack.top = R"("format": 2, )";
    // A duplicate key does not parse at all.
    CHECK(reports(read(pack).diagnostics, "pack.syntax"));

    const auto with_top = [](std::string replace, std::string by) {
        TestPack p;
        std::string text = p.text();
        const auto at = text.find(replace);
        REQUIRE(at != std::string::npos);
        text.replace(at, replace.size(), by);
        return read_pack(text);
    };
    CHECK(reports(with_top(R"("format": 1)", R"("format": 2)").diagnostics, "pack.format",
                  {{"value", "2"}}));
    CHECK(reports(with_top(R"("edition": 1)", R"("edition": 2)").diagnostics, "pack.edition",
                  {{"value", "2"}}));
    CHECK(reports(with_top(R"("id": "test")", R"("id": "1test")").diagnostics, "pack.bad-id"));
    CHECK(reports(with_top(R"("id": "test")", R"("id": "te--st")").diagnostics, "pack.bad-id"));
    CHECK(reports(with_top(R"("language": "qaa")", R"("language": "q")").diagnostics,
                  "pack.bad-language"));
    CHECK(reports(with_top(R"("version": 1)", R"("version": 0)").diagnostics, "pack.bad-version"));
    CHECK(reports(with_top(R"("official": false)", R"("official": "no")").diagnostics,
                  "pack.expected-boolean"));
    CHECK(reports(with_top(R"("name": "Test")", R"("name": "")").diagnostics, "pack.bad-text"));
    CHECK(reports(with_top(R"("name": "Test")", R"("name": "Test", "extra": 1)").diagnostics,
                  "pack.unknown-key", {{"path", "."}, {"key", "extra"}}));
    CHECK(reports(with_top(R"("name": "Test", )", "").diagnostics, "pack.missing-key",
                  {{"key", "name"}}));
    CHECK(reports(with_top(R"("separation": "spaces")", R"("separation": "tabs")").diagnostics,
                  "pack.bad-value", {{"path", "reading/separation"}}));

    // Many problems at once, each reported.
    const PackRead many = with_top(R"("version": 1, "language": "qaa", "name": "Test")",
                                   R"("version": 0, "language": "q", "name": "")");
    CHECK(reports(many.diagnostics, "pack.bad-version"));
    CHECK(reports(many.diagnostics, "pack.bad-language"));
    CHECK(reports(many.diagnostics, "pack.bad-text", {{"path", "name"}}));

    // At most max_diagnostics, then a note.
    TestPack noisy;
    for (int i = 0; i < 150; ++i) {
        noisy.vocabulary += (i == 0 ? "" : ", ") + std::format(R"("act.x{}": "x")", i);
    }
    const PackRead flood = read(noisy);
    CHECK(flood.diagnostics.size() == max_diagnostics + 1);
    CHECK(flood.diagnostics.back().code == "bo.truncated");
    CHECK(render(flood.diagnostics.back(), official_pack("zh-Hans-CN")) ==
          "还有其他问题；只显示前 100 个");
}

TEST_CASE("reading rules: prefixes, attaching words, punctuation, multipliers, dates",
          "[bo][packs]") {
    const auto with = [](std::string reading, std::string vocabulary = "") {
        TestPack pack;
        pack.reading = std::move(reading);
        pack.vocabulary = std::move(vocabulary);
        return pack;
    };
    // Prefixes are keywords of one word.
    must_read(with(R"("prefixes": ["kw.can", "kw.requires"], )"));
    refuses(with(R"("prefixes": ["act.pay"], )", R"("act.pay": "payq")"), "pack.wrong-category");
    refuses(with(R"("prefixes": ["kw.fly"], )"), "pack.unknown-concept");
    // Attaching words: spelled here, of one word, with the argument's place
    // away from the neighbour; categories by name, keywords excluded.
    must_read(with(R"("attach": [{"word": "price.per", "before": ["unit", "currency"]}], )",
                   R"("price.per": "perq")"));
    refuses(with(R"("attach": [{"word": "price.per", "before": ["unit"]}], )"), "pack.bad-attach");
    refuses(with(R"("attach": [{"word": "price.per", "before": ["planet"]}], )",
                 R"("price.per": "perq")"),
            "pack.unknown-category", {{"category", "planet"}});
    refuses(with(R"("attach": [{"word": "price.per", "before": ["keyword"]}], )",
                 R"("price.per": "perq")"),
            "pack.unknown-category");
    refuses(with(R"("attach": [{"word": "price.per"}], )", R"("price.per": "perq")"),
            "pack.bad-attach");
    refuses(with(R"("attach": [{"word": "kw.can", "before": ["unit"]}], )"), "pack.wrong-category");
    refuses(with(R"("attach": [{"word": "cond.within", "before": ["unit"]}], )",
                 R"("cond.within": "… nq")"),
            "pack.bad-attach"); // the place is on the neighbour's side
    must_read(with(R"("attach": [{"word": "cond.within", "after": ["unit"]}], )",
                   R"("cond.within": "… nq")"));
    refuses(with(R"("attach": [{"word": "price.setup_fee", "before": ["unit"]}], )",
                 R"("price.setup_fee": "setup feeq")"),
            "pack.bad-attach"); // two words
    // Punctuation: a character no word contains, for an ASCII one.
    must_read(with(R"("punctuation": {"，": ",", "「": "\"", "\u3000": " "}, )"));
    refuses(with(R"("punctuation": {"a": ","}, )"), "pack.bad-punctuation");
    refuses(with(R"("punctuation": {"字": ","}, )"), "pack.bad-punctuation");
    refuses(with(R"("punctuation": {"，，": ","}, )"), "pack.bad-punctuation");
    refuses(with(R"("punctuation": {"，": "x"}, )"), "pack.bad-punctuation");
    refuses(with(R"("punctuation": {"，": ",,"}, )"), "pack.bad-punctuation");
    // Multipliers: powers of ten.
    must_read(with(R"("multipliers": {"lakh": 100000, "crore": 10000000}, )"));
    refuses(with(R"("multipliers": {"dozen": 12}, )"), "pack.bad-multiplier", {{"value", "12"}});
    refuses(with(R"("multipliers": {"m q": 1000}, )"), "pack.bad-spelling");
    refuses(with(R"("multipliers": {"x": 1}, )"), "pack.bad-multiplier");
    // A multiplier spelled like a word means two things.
    refuses(with(R"("multipliers": {"payq": 1000}, )", R"("act.pay": "payq")"),
            "pack.duplicate-spelling");
    // Dates.
    must_read(with(R"("dates": {"read": ["{D}.{M}.{Y}"], "write": "{D}.{M}.{Y}"}, )"));
    must_read(with(
        R"("dates": {"write": "{MONTH} {D}, {Y}", "months": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]}, )"));
    refuses(with(R"("dates": {"write": "{Y}{M}{D}"}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"write": "{Y}-{M}"}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"write": "{Y}-{M}-{D}-{D}"}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"write": "{Y}-{X}-{D}"}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"read": ["{Y} {M} {D}"], "write": "{Y}-{M}-{D}"}, )"),
            "pack.bad-date"); // read patterns are one word
    refuses(with(R"("dates": {"read": ["{Y}-{MONTH}-{D}"], "write": "{Y}-{M}-{D}"}, )"),
            "pack.bad-date");
    refuses(with(R"("dates": {"write": "{MONTH} {D}, {Y}"}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"write": "{Y}-{M}-{D}", "months": ["a"]}, )"), "pack.bad-date");
    refuses(with(R"("dates": {"read": []}, )"), "pack.missing-key", {{"key", "write"}});
}

TEST_CASE("messages and sentences use their own placeholders", "[bo][packs]") {
    const auto with = [](std::string top) {
        TestPack pack;
        pack.top = std::move(top);
        return pack;
    };
    must_read(with(R"("messages": {"pack.missing-key": "{path}: {key}?"}, )"
                   R"("sentences": {"party-action": "{party} {action.third}"}, )"));
    refuses(with(R"("messages": {"pack.nope": "x"}, )"), "pack.unknown-message",
            {{"code", "pack.nope"}});
    refuses(with(R"("sentences": {"nope": "x"}, )"), "pack.unknown-sentence");
    refuses(with(R"("messages": {"pack.missing-key": "{who}"}, )"), "pack.bad-placeholder",
            {{"placeholder", "who"}});
    refuses(with(R"("messages": {"pack.missing-key": "{path.third}"}, )"),
            "pack.bad-placeholder"); // forms are for sentences
    refuses(with(R"("messages": {"pack.missing-key": "{path"}, )"), "pack.bad-placeholder");
    refuses(with(R"("messages": {"pack.missing-key": "path}"}, )"), "pack.bad-placeholder");
    refuses(with(R"("sentences": {"party-action": "{party.Third}"}, )"), "pack.bad-placeholder");
    refuses(with(R"("messages": {"pack.missing-key": "a\nb"}, )"), "pack.bad-text");

    // A pack's messages are used, English fills in.
    TestPack own = with(R"("messages": {"pack.missing-key": "{path} lacks {key}"}, )");
    const Pack pack = must_read(own);
    const Diagnostic missing{
        "pack.missing-key", {{"path", "reading"}, {"key", "separation"}}, Span{}};
    CHECK(render(missing, &pack) == "reading lacks separation");
    CHECK(render(missing, nullptr) == "reading needs the key separation");
    CHECK(render(missing, official_pack("zh-Hant-HK")) == "reading 須有鍵 separation");
    CHECK(render(missing, official_pack("zh-Hans-CN")) == "reading 缺少键 separation");
    const Diagnostic other{"pack.duplicate-id", {{"pack", "x"}}, Span{}};
    CHECK(render(other, &pack) == "two packs have the id x");
    CHECK(fill("{a}{b}{a}{c", std::vector<std::pair<std::string_view, std::string>>{
                                  {"a", "1"}, {"b", "2"}}) == "121{c");
}

TEST_CASE("only the packs the compiler carries are official", "[bo][packs]") {
    // The official file, given again: the same pack, taken once.
    const PackRead same = read_pack(official_pack_texts()[1].text);
    REQUIRE(same.pack);
    PackSetRead r = make_pack_set({*same.pack});
    REQUIRE(r.set);
    CHECK(r.set->packs().size() == 3);

    // A changed copy that still calls itself official.
    std::string text(official_pack_texts()[0].text);
    text.replace(text.find("\"name\": \"English\""), 17, "\"name\": \"English!\"");
    const PackRead changed = read_pack(text);
    REQUIRE(changed.pack);
    r = make_pack_set({*changed.pack});
    CHECK_FALSE(r.set);
    CHECK(reports(r.diagnostics, "pack.false-official", {{"pack", "en"}}));

    // A community pack under an official id.
    TestPack copy;
    copy.id = "en";
    r = make_pack_set({must_read(copy)});
    CHECK_FALSE(r.set);
    CHECK(reports(r.diagnostics, "pack.duplicate-id", {{"pack", "en"}}));
    // Two community packs under one id.
    TestPack one;
    one.id = "company";
    r = make_pack_set({must_read(one), must_read(one)});
    CHECK(reports(r.diagnostics, "pack.duplicate-id", {{"pack", "company"}}));
}

TEST_CASE("comments and the diagnostic notation of packs", "[bo][packs]") {
    TestPack pack;
    std::string text = "# a header\n/ and a block comment /\n" + pack.text() + "\n# the end\n";
    const PackRead r = read_pack(text);
    REQUIRE(r.pack);
    CHECK(r.pack->canonical == must_read(pack).canonical);
    CHECK(reports(read_pack("{/ never closed").diagnostics, "pack.syntax"));
}
