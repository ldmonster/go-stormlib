// stormlib-parity-c: StormLib-backed parity harness matching golang/tools/paritycmd contract.
#include <StormLib.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

const char kVersion[] = "v0.1.0-contract1";

struct FileEntry {
    std::string name;
    DWORD hashA = 0;
    DWORD hashB = 0;
    USHORT locale = 0;
    BYTE platform = 0;
    DWORD blockIndex = 0;
};

static bool parse_uint(const char *s, unsigned long long &out, int bits) {
    if (!s || !*s)
        return false;
    int base = 10;
    const char *p = s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    }
    char *end = nullptr;
    unsigned long long v = std::strtoull(p, &end, base);
    if (end == p || *end != '\0')
        return false;
    unsigned long long max = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
    if (v > max)
        return false;
    out = v;
    return true;
}

// JSON string contents for "payload" field (escaped for embedding in JSON object).
static std::string json_escape_payload(const std::vector<char> &raw) {
    std::string o;
    o.reserve(raw.size() + 8);
    for (unsigned char c : raw) {
        switch (c) {
        case '"':
            o += "\\\"";
            break;
        case '\\':
            o += "\\\\";
            break;
        case '\b':
            o += "\\b";
            break;
        case '\f':
            o += "\\f";
            break;
        case '\n':
            o += "\\n";
            break;
        case '\r':
            o += "\\r";
            break;
        case '\t':
            o += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                o += buf;
            } else {
                o.push_back(static_cast<char>(c));
            }
        }
    }
    return o;
}

static void print_json_obj_lookup(const std::string &outcome,
                                  const std::string &payload_esc,
                                  const std::string &tier) {
    std::cout << "{\"outcome\":\"" << outcome << "\"";
    if (outcome == "ok") {
        std::cout << ",\"payload\":\"" << payload_esc << "\""
                  << ",\"tier\":\"" << tier << "\"";
    }
    std::cout << "}\n";
}

static void print_json_obj_read(const std::string &outcome, const std::string &payload_esc) {
    std::cout << "{\"outcome\":\"" << outcome << "\"";
    if (outcome == "ok")
        std::cout << ",\"payload\":\"" << payload_esc << "\"";
    std::cout << "}\n";
}

// Go-built fixtures now encrypt tables with Storm-compatible SaveMpqTable layout; Storm's
// in-memory hash table matches Go's decoded rows. Enumerate slots with pseudo-names File########.xxx.
static bool collect_files(HANDLE mpq, std::vector<FileEntry> &out) {
    DWORD nHash = 0;
    DWORD pcb = 0;
    if (!SFileGetFileInfo(mpq, SFileMpqHashTableSize, &nHash, sizeof(nHash), &pcb))
        return false;
    if (nHash == 0)
        return true;

    std::vector<TMPQHash> htab(nHash);
    pcb = 0;
    if (!SFileGetFileInfo(mpq, SFileMpqHashTable, htab.data(),
                          (DWORD)(nHash * sizeof(TMPQHash)), &pcb))
        return false;

    DWORD nBlock = 0;
    pcb = 0;
    if (!SFileGetFileInfo(mpq, SFileMpqBlockTableSize, &nBlock, sizeof(nBlock), &pcb))
        return false;
    if (nBlock == 0)
        return true;

    // Mirror Go's materialized index: one row per hash-table slot that points at an
    // existing block. Use Storm's pseudo-name scheme (see StringCreatePseudoFileName /
    // SFileOpenFileEx) so SFileOpenFileEx can open the file for payload reads.
    char nameBuf[MAX_PATH];
    for (DWORD i = 0; i < nHash; i++) {
        const TMPQHash &he = htab[i];
        DWORD bi = he.dwBlockIndex & BLOCK_INDEX_MASK;
        if (bi == HASH_ENTRY_FREE || bi == HASH_ENTRY_DELETED)
            continue;
        if (bi >= nBlock)
            continue;

        std::snprintf(nameBuf, sizeof(nameBuf), "File%08u.xxx", bi);
        FileEntry e;
        e.name = nameBuf;
        e.hashA = he.dwHashCheck1;
        e.hashB = he.dwHashCheck2;
        e.locale = he.Locale;
        e.platform = he.Platform;
        e.blockIndex = bi;
        out.push_back(std::move(e));
    }
    return true;
}

static bool cmp_group_order(const FileEntry &a, const FileEntry &b) {
    if (a.locale != b.locale)
        return a.locale < b.locale;
    if (a.platform != b.platform)
        return a.platform < b.platform;
    return a.blockIndex < b.blockIndex;
}

static const FileEntry *find_indexed_entry(const std::vector<FileEntry> &group,
                                           USHORT locale,
                                           BYTE platform) {
    for (const FileEntry &e : group) {
        if (e.locale == locale && e.platform == platform)
            return &e;
    }
    for (const FileEntry &e : group) {
        if (e.locale == locale && e.platform == 0)
            return &e;
    }
    for (const FileEntry &e : group) {
        if (e.locale == 0 && e.platform == platform)
            return &e;
    }
    for (const FileEntry &e : group) {
        if (e.locale == 0 && e.platform == 0)
            return &e;
    }
    return nullptr;
}

static std::string lookup_tier(const FileEntry &e, USHORT locale, BYTE platform) {
    if (e.locale == locale && e.platform == platform)
        return "exact";
    if (e.locale == locale && e.platform == 0)
        return "locale-neutral-platform";
    if (e.locale == 0 && e.platform == platform)
        return "neutral-locale-platform";
    return "fully-neutral";
}

static bool read_file_whole(HANDLE mpq, const char *path, std::vector<char> &buf, bool &decode_fail) {
    decode_fail = false;
    HANDLE hFile = nullptr;
    if (!SFileOpenFileEx(mpq, path, SFILE_OPEN_FROM_MPQ, &hFile))
        return false;
    DWORD high = 0;
    DWORD low = SFileGetFileSize(hFile, &high);
    ULONGLONG sz = (static_cast<ULONGLONG>(high) << 32) | low;
    if (sz > 0x40000000ULL) {
        SFileCloseFile(hFile);
        decode_fail = true;
        return false;
    }
    buf.resize(static_cast<size_t>(sz));
    ULONGLONG total = 0;
    while (total < sz) {
        DWORD chunk = 0;
        DWORD toread = static_cast<DWORD>(std::min<ULONGLONG>(sz - total, 0xFFFFFFFFULL));
        if (!SFileReadFile(hFile, buf.data() + static_cast<size_t>(total), toread, &chunk,
                           nullptr) ||
            chunk == 0) {
            decode_fail = true;
            SFileCloseFile(hFile);
            return false;
        }
        total += chunk;
    }
    SFileCloseFile(hFile);
    return total == sz;
}

static bool open_mpq(const char *path, bool force_v1, DWORD marker, HANDLE *mpq) {
    if (marker != 0) {
        SFILE_MARKERS m{};
        m.dwSize = sizeof(SFILE_MARKERS);
        m.dwSignature = marker;
        m.szHashTableKey = nullptr;
        m.szBlockTableKey = nullptr;
        if (!SFileSetArchiveMarkers(&m))
            return false;
    }
    DWORD flags = STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE | MPQ_OPEN_READ_ONLY;
    if (force_v1)
        flags |= MPQ_OPEN_FORCE_MPQ_V1;
    return SFileOpenArchive(path, 0, flags, mpq);
}

static int usage_error(const char *msg) {
    std::cerr << msg << "\n";
    return 1;
}

static int run_open(const char *path, bool force_v1, DWORD marker) {
    HANDLE mpq = nullptr;
    if (!open_mpq(path, force_v1, marker, &mpq)) {
        std::cout << "open-fail\n";
        return 0;
    }
    SFileCloseArchive(mpq);
    std::cout << "open-ok\n";
    return 0;
}

static int run_lookup(const char *path,
                      bool force_v1,
                      DWORD marker,
                      USHORT locale,
                      BYTE platform) {
    if (std::getenv("STORMLIB_PARITY_DISABLE_REPORT") != nullptr &&
        std::string(std::getenv("STORMLIB_PARITY_DISABLE_REPORT")) == "true") {
        std::cerr << "unsupported report mode\n";
        return 2;
    }
    HANDLE mpq = nullptr;
    if (!open_mpq(path, force_v1, marker, &mpq)) {
        print_json_obj_lookup("unsupported", "", "");
        return 0;
    }

    std::vector<FileEntry> files;
    if (!collect_files(mpq, files)) {
        SFileCloseArchive(mpq);
        return usage_error("find files failed");
    }

    std::map<std::pair<DWORD, DWORD>, std::vector<FileEntry>> groups;
    for (const FileEntry &e : files) {
        groups[{e.hashA, e.hashB}].push_back(e);
    }

    std::vector<std::pair<DWORD, DWORD>> keys;
    keys.reserve(groups.size());
    for (const auto &kv : groups) {
        keys.push_back(kv.first);
    }
    std::sort(keys.begin(), keys.end(), [](const std::pair<DWORD, DWORD> &a,
                                            const std::pair<DWORD, DWORD> &b) {
        if (a.first != b.first)
            return a.first < b.first;
        return a.second < b.second;
    });

    for (const auto &hk : keys) {
        std::vector<FileEntry> group = groups[hk];
        std::sort(group.begin(), group.end(), cmp_group_order);

        const FileEntry *winner = find_indexed_entry(group, locale, platform);
        if (!winner)
            continue;

        std::vector<char> payload;
        bool decode_fail = false;
        if (!read_file_whole(mpq, winner->name.c_str(), payload, decode_fail)) {
            if (decode_fail)
                print_json_obj_lookup("decode-fail", "", "");
            else
                print_json_obj_lookup("not-found", "", "");
            SFileCloseArchive(mpq);
            return 0;
        }
        std::string esc = json_escape_payload(payload);
        print_json_obj_lookup("ok", esc, lookup_tier(*winner, locale, platform));
        SFileCloseArchive(mpq);
        return 0;
    }

    print_json_obj_lookup("not-found", "", "");
    SFileCloseArchive(mpq);
    return 0;
}

static int run_read(const char *path,
                    bool force_v1,
                    DWORD marker,
                    DWORD hashA,
                    DWORD hashB,
                    USHORT locale,
                    BYTE platform) {
    if (std::getenv("STORMLIB_PARITY_DISABLE_REPORT") != nullptr &&
        std::string(std::getenv("STORMLIB_PARITY_DISABLE_REPORT")) == "true") {
        std::cerr << "unsupported report mode\n";
        return 2;
    }
    HANDLE mpq = nullptr;
    if (!open_mpq(path, force_v1, marker, &mpq)) {
        print_json_obj_read("unsupported", "");
        return 0;
    }

    std::vector<FileEntry> files;
    if (!collect_files(mpq, files)) {
        SFileCloseArchive(mpq);
        return usage_error("find files failed");
    }

    std::vector<FileEntry> group;
    for (const FileEntry &e : files) {
        if (e.hashA == hashA && e.hashB == hashB)
            group.push_back(e);
    }
    std::sort(group.begin(), group.end(), cmp_group_order);

    const FileEntry *winner = find_indexed_entry(group, locale, platform);
    if (!winner) {
        print_json_obj_read("not-found", "");
        SFileCloseArchive(mpq);
        return 0;
    }

    std::vector<char> payload;
    bool decode_fail = false;
    if (!read_file_whole(mpq, winner->name.c_str(), payload, decode_fail)) {
        print_json_obj_read(decode_fail ? "decode-fail" : "not-found", "");
        SFileCloseArchive(mpq);
        return 0;
    }
    print_json_obj_read("ok", json_escape_payload(payload));
    SFileCloseArchive(mpq);
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    bool force_v1 = false;
    DWORD marker = 0;
    bool report_lookup = false;
    bool report_read = false;
    std::vector<char *> pos;

    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--version")) {
            std::cout << kVersion << "\n";
            return 0;
        }
        if (!std::strcmp(argv[i], "--force-v1")) {
            force_v1 = true;
            continue;
        }
        if (!std::strcmp(argv[i], "--marker")) {
            if (i + 1 >= argc)
                return usage_error("missing --marker value");
            unsigned long long v = 0;
            if (!parse_uint(argv[++i], v, 32))
                return usage_error("invalid marker");
            marker = static_cast<DWORD>(v);
            continue;
        }
        if (!std::strcmp(argv[i], "--report-lookup")) {
            report_lookup = true;
            continue;
        }
        if (!std::strcmp(argv[i], "--report-read")) {
            report_read = true;
            continue;
        }
        if (argv[i][0] == '-')
            return usage_error("unknown flag");
        pos.push_back(argv[i]);
    }

    if (report_lookup && report_read)
        return usage_error("only one report mode can be selected");

    if (report_lookup) {
        if (pos.size() != 3)
            return usage_error("report-lookup requires <locale> <platform> <archive>");
        unsigned long long loc = 0, plat = 0;
        if (!parse_uint(pos[0], loc, 16) || !parse_uint(pos[1], plat, 8))
            return usage_error("invalid locale/platform");
        return run_lookup(pos[2], force_v1, marker, static_cast<USHORT>(loc),
                          static_cast<BYTE>(plat));
    }
    if (report_read) {
        if (pos.size() != 5)
            return usage_error("report-read requires <hashA> <hashB> <locale> <platform> <archive>");
        unsigned long long ha = 0, hb = 0, loc = 0, plat = 0;
        if (!parse_uint(pos[0], ha, 32) || !parse_uint(pos[1], hb, 32) ||
            !parse_uint(pos[2], loc, 16) || !parse_uint(pos[3], plat, 8))
            return usage_error("invalid numeric args");
        return run_read(pos[4], force_v1, marker, static_cast<DWORD>(ha),
                        static_cast<DWORD>(hb), static_cast<USHORT>(loc),
                        static_cast<BYTE>(plat));
    }
    if (pos.size() != 1)
        return usage_error("default mode requires <archive>");
    return run_open(pos[0], force_v1, marker);
}
