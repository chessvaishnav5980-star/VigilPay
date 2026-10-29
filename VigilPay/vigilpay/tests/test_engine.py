import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import engine  # noqa: E402
import ai  # noqa: E402

CASES = [
    ("A stranger asked me to scan a QR to receive money and it asks for my PIN", "scam", "qr-receive"),
    ("I got a message my refund failed, click this link to claim cashback", "scam", "refund-cashback"),
    ("Someone from the bank called, my KYC expires today, he wants my OTP", "scam", "kyc-vishing"),
    ("support agent told me to install AnyDesk to fix my payment problem", "scam", "screen-share"),
    ("buyer on OLX wants to pay me, sent a request I should approve and enter pin", "scam", "fake-seller"),
    ("a stranger sent 5000 by mistake and is asking me to return the money", "scam", "accidental-payment"),
    ("I searched google for the customer care number and they asked me to share my otp", "scam", "fake-customer-care"),
    ("you have won a lottery, pay a fee to get the prize", "scam", "lottery-prize"),
    ("telegram group part time job, deposit money to unlock tasks and withdraw", "scam", "job-task"),
    ("sms says electricity will be disconnected tonight, call the officer", "scam", "electricity-bill"),
    ("customer showed payment success screenshot but I got no sms", "scam", "fake-screenshot"),
    ("instant loan app asked processing fee and access to my contacts", "scam", "loan-app"),
    ("new number says he is my cousin, accident, needs money urgently", "scam", "family-emergency"),
    ("someone sent me a 6 digit code by mistake and asks me to forward it", "scam", "whatsapp-code"),
    ("I got RTO_Challan.apk on whatsapp asking me to install it", "scam", "apk-file"),
    ("video call from police, parcel with drugs in my name, stay on the call and pay money", "scam", "digital-arrest"),
]

SAFE = [
    "I am paying at a shop by scanning the shopkeeper's QR",
    "I want to send rent to my landlord using his UPI ID",
    "how do I check my bank balance",
]

def test_every_scenario_detected():
    for text, level, sid in CASES:
        r = engine.analyze(text)
        assert r["level"] == level, (text, r["level"], r["risk"])
        assert r["scenario"]["id"] == sid, (text, r["scenario"] and r["scenario"]["id"])

def test_normal_payments_not_flagged_as_scam():
    for text in SAFE:
        r = engine.analyze(text)
        assert r["level"] == "safe", (text, r["level"], r["risk"])

def test_no_pin_asked_lowers_risk():
    risky = engine.analyze("a stranger sent me a QR to receive money")
    calmer = engine.analyze("a stranger sent me a QR to receive money but they did not ask for my pin")
    assert calmer["risk"] <= risky["risk"]

def test_sensitive_numbers_detected_and_redacted():
    assert engine.analyze("my pin is 4821")["sensitiveWarning"] is True
    assert engine.analyze("they called me")["sensitiveWarning"] is False

def test_fifteen_plus_scenarios_with_required_fields():
    sc = engine.scenario_list()
    assert len(sc) >= 15
    for s in sc:
        assert s["why"] and s["actions"] and s["redFlags"] and s["source"]

def test_ai_reply_guard():
    assert ai._safe("This looks like a scam. Never share your OTP. Call 1930.")
    assert not ai._safe("Please share your OTP so I can verify.")
    assert not ai._safe("Send your UPI PIN here")

def test_asking_for_otp_or_pin_is_never_safe():
    for text in ["someone says send otp", "a man on the phone wants my upi pin", "they told me to share the otp"]:
        assert engine.analyze(text)["level"] != "safe", text

def test_own_pin_entry_for_normal_payment_not_flagged():
    assert engine.analyze("I enter my pin to pay at the shop")["level"] == "safe"


if __name__ == "__main__":
    import traceback
    bad = 0
    for n in sorted(k for k in dir() if k.startswith("test_")):
        try:
            globals()[n](); print("PASS", n)
        except Exception:
            bad += 1; print("FAIL", n); traceback.print_exc(limit=2)
    raise SystemExit(bad)
