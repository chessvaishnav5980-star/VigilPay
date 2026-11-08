// redflag_scanner: counts scam red-flag phrases in a text file (one message per line).
// Build: g++ -O2 -std=c++17 -o redflag_scanner redflag_scanner.cpp   Run: ./redflag_scanner messages.txt
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

struct Flag { std::string name; std::vector<std::string> phrases; int weight; };

static const std::vector<Flag> FLAGS = {
    {"Asks for PIN/OTP",      {"your pin", "upi pin", "your otp", "share otp", "send otp", "verification code"}, 3},
    {"Urgency / threat",      {"urgent", "immediately", "expires today", "blocked", "suspended", "last chance", "tonight"}, 2},
    {"Screen-share app",      {"anydesk", "teamviewer", "quicksupport", "screen share"}, 4},
    {"Prize / refund bait",   {"lottery", "you won", "cashback", "refund", "reward", "free gift"}, 2},
    {"Advance payment",       {"advance", "token amount", "processing fee", "registration fee", "pay first"}, 3},
    {"Fake authority",        {"bank officer", "customs", "cbi", "police case", "npci", "kyc"}, 2},
    {"Secrecy",               {"don't tell", "do not tell", "keep it secret", "stay on the call"}, 3},
    {"Suspicious file/link",  {".apk", "click this link", "install this app"}, 3},
};

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string level(int score) { return score >= 6 ? "LIKELY SCAM" : score >= 3 ? "BE CAREFUL" : "LOOKS OK"; }

int main(int argc, char** argv) {
    std::ifstream file;
    std::istream* in = &std::cin;
    if (argc > 1) {
        file.open(argv[1]);
        if (!file) { std::cerr << "Cannot open " << argv[1] << "\n"; return 1; }
        in = &file;
    }
    std::map<std::string, int> seen;
    int lines = 0, scams = 0, careful = 0;
    std::string line;
    while (std::getline(*in, line)) {
        if (line.empty()) continue;
        ++lines;
        std::string t = lower(line);
        int score = 0;
        std::vector<std::string> hit;
        for (const auto& f : FLAGS) {
            for (const auto& p : f.phrases) {
                if (t.find(p) != std::string::npos) { score += f.weight; hit.push_back(f.name); ++seen[f.name]; break; }
            }
        }
        std::string lv = level(score);
        if (lv == "LIKELY SCAM") ++scams; else if (lv == "BE CAREFUL") ++careful;
        std::cout << "[" << lv << " " << score << "] " << line.substr(0, 70) << (line.size() > 70 ? "..." : "") << "\n";
        for (const auto& h : hit) std::cout << "      - " << h << "\n";
    }
    std::cout << "\nScanned " << lines << " messages: " << scams << " likely scam, " << careful << " be careful.\n";
    std::vector<std::pair<std::string, int>> ranked(seen.begin(), seen.end());
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b) { return a.second > b.second; });
    if (!ranked.empty()) {
        std::cout << "Most common red flags:\n";
        for (const auto& r : ranked) std::cout << "  " << r.second << " x " << r.first << "\n";
    }
    return 0;
}
