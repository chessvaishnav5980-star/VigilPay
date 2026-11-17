import java.util.*;
import java.util.regex.*;

public class UpiIdChecker {

    private static final Pattern VPA = Pattern.compile("^[a-zA-Z0-9.\\-_]{2,50}@[a-zA-Z]{2,30}$");

    private static final Set<String> KNOWN = new HashSet<>(Arrays.asList(
        "oksbi", "okhdfcbank", "okicici", "okaxis", "ybl", "ibl", "axl", "paytm", "apl",
        "sbi", "hdfcbank", "icici", "axisbank", "upi", "postbank", "pnb", "boi", "cnrb", "unionbank", "kotak"));

    private static final String[] BAIT = {"refund", "reward", "cashback", "support", "helpdesk", "kyc", "official", "care", "lottery", "prize", "verify"};

    static class Result {
        final String id; final List<String> notes = new ArrayList<>(); int risk = 0; boolean validFormat;
        Result(String id) { this.id = id; }
    }

    static Result check(String raw) {
        Result r = new Result(raw);
        String id = raw == null ? "" : raw.trim();
        r.validFormat = VPA.matcher(id).matches();
        if (!r.validFormat) {
            r.notes.add("Not a valid UPI ID format. It should look like name@bank.");
            r.risk = 2;
            return r;
        }
        String[] parts = id.toLowerCase().split("@");
        String handle = parts[0], provider = parts[1];

        if (!KNOWN.contains(provider)) { r.notes.add("Unfamiliar provider '@" + provider + "'. Check the receiver's name carefully."); r.risk += 1; }
        for (String b : BAIT) if (handle.contains(b)) { r.notes.add("Handle contains '" + b + "', a word scammers use to look official."); r.risk += 2; break; }
        if (handle.matches(".*\\d{8,}.*") && !handle.matches("^\\d{10}$")) { r.notes.add("Long run of digits in the handle."); r.risk += 1; }
        if (handle.matches(".*[0o]{3,}.*|.*[1l]{3,}.*")) { r.notes.add("Repeated look-alike characters (0/o, 1/l)."); r.risk += 1; }
        if (r.notes.isEmpty()) r.notes.add("Format looks normal. Still confirm the name shown matches the person or shop.");
        return r;
    }

    static String label(int risk) { return risk >= 3 ? "HIGH" : risk >= 1 ? "MEDIUM" : "LOW"; }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java UpiIdChecker <upi-id> [more ids...]");
            System.out.println("Never type your PIN or OTP into any tool.");
            return;
        }
        for (String a : args) {
            Result r = check(a);
            System.out.printf("%n%s%n  format: %s | risk: %s%n", r.id, r.validFormat ? "valid" : "invalid", label(r.risk));
            for (String n : r.notes) System.out.println("  - " + n);
        }
        System.out.println("\nIf you lost money: call 1930 or visit cybercrime.gov.in");
    }
}
