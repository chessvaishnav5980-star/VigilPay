#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

struct Rule { const char* name; int score; std::vector<std::string> words; };

int main() {
    std::string text((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c){ return std::tolower(c); });
    const std::vector<Rule> rules = {
        {"Credential theft",34,{"otp","upi pin","cvv","password","card pin"}},
        {"Remote access",35,{"anydesk","teamviewer","remote access","share your screen"}},
        {"Forced urgency",16,{"urgent","immediately","act now","account will be blocked"}},
        {"Fear and authority",24,{"police","cbi","customs","arrest","warrant"}},
        {"Secrecy",22,{"do not tell","don't tell","do not hang up","stay on the call"}},
        {"Advance fee",24,{"registration fee","security deposit","processing fee","clearance fee"}}
    };
    int score=0; std::vector<std::string> matches;
    for (const auto& rule:rules) {
        bool found=std::any_of(rule.words.begin(),rule.words.end(),[&](const std::string& word){return text.find(word)!=std::string::npos;});
        if(found){score+=rule.score;matches.emplace_back(rule.name);}
    }
    if(matches.size()>=3)score+=8; score=std::min(score,100);
    const char* level=score>=70?"high":score>=30?"suspicious":"low";
    std::cout<<"{\"engine\":\"cpp\",\"score\":"<<score<<",\"level\":\""<<level<<"\",\"matches\":[";
    for(std::size_t i=0;i<matches.size();++i)std::cout<<(i?",\"":"\"")<<matches[i]<<"\"";
    std::cout<<"]}\n";
}
