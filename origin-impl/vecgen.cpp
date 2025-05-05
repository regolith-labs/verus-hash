/* vecgen.cpp  – generate VerusHash-v2.2 test vectors
 *
 * Build from inside verus-hash/verus/c/ with:
 *     make vecgen         # or:  g++ …  (see Makefile below)
 *
 * Usage examples
 *     ./vecgen                         # default 80-byte 0x00..0x4F header
 *     ./vecgen abc                     # ASCII “abc”
 *     ./vecgen 00:01:02:03             # raw hex bytes (colon/space optional)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "verus_hash.h"        // exposes verus_hash_v2()

// ------------------------------------------------------------------ helpers --
static std::vector<uint8_t> parse_arg(int argc,char**argv) {
    if (argc == 1) {                         // default 80-byte header 00..4F
        std::vector<uint8_t> v(80);
        for (size_t i=0;i<80;i++) v[i]=static_cast<uint8_t>(i);
        return v;
    }
    std::string s(argv[1]);
    // try plain ASCII first
    if (s.find_first_of("0123456789abcdefABCDEF: ") == std::string::npos) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    // otherwise treat as hex list
    std::vector<uint8_t> v;
    size_t pos=0;
    while (pos<s.size()) {
        while (pos<s.size() && (s[pos]==':'||s[pos]==' ')) ++pos;
        if (pos+2>s.size()) break;
        v.push_back(static_cast<uint8_t>(std::strtoul(s.substr(pos,2).c_str(),nullptr,16)));
        pos+=2;
    }
    return v;
}
// ---------------------------------------------------------------------------

int main(int argc,char**argv)
{
    std::vector<uint8_t> msg = parse_arg(argc,argv);

    uint8_t digest[32];
    verus_hash_v2(digest, msg.data(), msg.size());

    for (unsigned char b: digest) std::printf("%02x", b);
    std::puts("");
    return 0;
}
