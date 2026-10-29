import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Optional offline Java reference engine. No dependency or network access. */
public final class VigilPayRiskEngine {
    private record Rule(String name, int score, String[] words) {}

    private static final Rule[] RULES = {
        new Rule("Credential theft", 34, new String[]{"otp", "upi pin", "cvv", "password", "card pin"}),
        new Rule("Remote access", 35, new String[]{"anydesk", "teamviewer", "remote access", "share your screen"}),
        new Rule("Forced urgency", 16, new String[]{"urgent", "immediately", "act now", "account will be blocked"}),
        new Rule("Fear and authority", 24, new String[]{"police", "cbi", "customs", "arrest", "warrant"}),
        new Rule("Secrecy", 22, new String[]{"do not tell", "don't tell", "do not hang up", "stay on the call"}),
        new Rule("Advance fee", 24, new String[]{"registration fee", "security deposit", "processing fee", "clearance fee"})
    };

    public static void main(String[] args) {
        String text = String.join(" ", args).toLowerCase(Locale.ROOT);
        List<String> matches = new ArrayList<>();
        int score = 0;
        for (Rule rule : RULES) {
            boolean found = false;
            for (String word : rule.words()) if (text.contains(word)) { found = true; break; }
            if (found) { score += rule.score(); matches.add(rule.name()); }
        }
        if (matches.size() >= 3) score += 8;
        score = Math.min(score, 100);
        String level = score >= 70 ? "high" : score >= 30 ? "suspicious" : "low";
        System.out.printf("{\"engine\":\"java\",\"score\":%d,\"level\":\"%s\",\"matches\":[", score, level);
        for (int i=0; i<matches.size(); i++) System.out.printf("%s\"%s\"", i==0?"":",", matches.get(i));
        System.out.println("]}");
    }
}
