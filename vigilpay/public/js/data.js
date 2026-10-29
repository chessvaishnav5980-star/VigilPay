export const ALERTS = [
  { icon: "▦", title: "QR-to-receive payment trick", detail: "A QR payment screen sends money; it does not receive it.", age: "Safety rule" },
  { icon: "!", title: "Digital arrest calls", detail: "Threats using police, parcel or customs stories to demand secrecy.", age: "High impact" },
  { icon: "₹", title: "Part-time task deposits", detail: "Small early rewards are used to build trust before a large demand.", age: "Common pattern" }
];

export const SAMPLE_TEXT = {
  upi: "I am sending you ₹5,000. Scan this QR code and enter your UPI PIN immediately to receive the money. Do it in 5 minutes.",
  arrest: "I am calling from the police cyber cell. A parcel in your name contains illegal items. Stay on this video call, do not tell your family, and transfer the verification amount now or you will be arrested.",
  job: "Congratulations! You can earn ₹8,000 daily by liking videos. First pay a refundable registration fee. Limited slots—act now and message only on Telegram."
};

export const EMERGENCY_PLANS = {
  money: {
    title: "Money was sent or deducted",
    subtitle: "Report the financial fraud immediately; faster reporting can improve the chance of stopping movement of funds.",
    steps: [
      ["Now", "Call 1930", "Tell the operator your mobile number, bank or wallet, amount, transaction ID and time."],
      ["2", "Contact the bank or payment app", "Use the official number or in-app support. Ask them to flag the transaction and secure the account."],
      ["3", "Preserve evidence", "Save transaction screenshots, chats, phone numbers, links and call details. Do not edit the originals."],
      ["4", "Complete the online complaint", "Visit cybercrime.gov.in and keep the acknowledgement number safely."],
      ["5", "Secure affected accounts", "Change relevant passwords from a trusted device and review recent sessions or transactions."]
    ]
  },
  otp: {
    title: "OTP, PIN or password was shared",
    subtitle: "Assume the affected account or payment instrument may be at risk until secured.",
    steps: [
      ["Now", "Call the official provider", "Use the number on the card, official app or official website. Block or freeze the affected access."],
      ["2", "Change the exposed credential", "Use a trusted device. Never reuse a new password from another account."],
      ["3", "Check activity", "Review transactions, login alerts, beneficiaries and active devices. Report anything you do not recognize."],
      ["4", "Call 1930 if money moved", "Have the transaction details ready and then file the complaint at cybercrime.gov.in."],
      ["5", "Ignore follow-up recovery callers", "Scammers may impersonate support after the first incident. Verify independently."]
    ]
  },
  remote: {
    title: "A remote-access app was installed",
    subtitle: "End the scammer’s live access before doing anything else.",
    steps: [
      ["Now", "Disconnect the device", "Turn off Wi-Fi and mobile data. Do not open banking apps on the affected device."],
      ["2", "Remove remote access", "Uninstall the remote-control app and revoke accessibility, screen sharing and device-admin permissions."],
      ["3", "Secure accounts elsewhere", "From a different trusted device, change banking, email and important account passwords."],
      ["4", "Contact your bank", "Ask for a fraud review and temporary controls if the scammer saw banking information."],
      ["5", "Get the device checked", "Update the operating system and security tools; consider a professional review if access was extensive."]
    ]
  },
  identity: {
    title: "Identity documents or personal data were shared",
    subtitle: "Reduce the chance of impersonation and watch for follow-up misuse.",
    steps: [
      ["Now", "Stop further contact", "Do not send selfies, OTPs, signatures or more documents. Preserve the conversation."],
      ["2", "Secure linked accounts", "Change passwords for email and accounts connected to the exposed phone number or ID."],
      ["3", "Review official safeguards", "Use only the official UIDAI, income-tax, bank or provider channels relevant to what was shared."],
      ["4", "Report misuse or threats", "Use cybercrime.gov.in; call 1930 immediately if financial loss also occurred."],
      ["5", "Monitor carefully", "Watch for unexpected OTPs, SIM issues, account openings or credit activity."]
    ]
  }
};

export const QUIZ = [
  { channel: "Marketplace chat", text: "A buyer says: ‘I sent ₹2,000. Scan my QR and enter your UPI PIN to receive it.’", options: ["Scan it; the money is waiting", "Ask for their OTP instead", "Refuse—the QR initiates a payment", "Install their support app"], answer: 2, explain: "A UPI QR normally starts a payment. You do not enter a UPI PIN to receive money." },
  { channel: "Video call", text: "A person in a police uniform says you are under ‘digital arrest’ and must remain on camera while transferring a security deposit.", options: ["Pay to prove innocence", "Hang up and verify through official channels", "Share Aadhaar first", "Let them remotely inspect your phone"], answer: 1, explain: "‘Digital arrest’ is a scam tactic. Law enforcement does not require deposits or continuous video-call detention." },
  { channel: "SMS", text: "‘Your electricity will be disconnected tonight. Pay ₹10 at power-bill-secure.help in 15 minutes.’", options: ["Use the link quickly", "Reply with account details", "Check the bill only through the official provider app/site", "Forward your OTP"], answer: 2, explain: "Urgency plus an unfamiliar domain is dangerous. Open the official provider app or type the known address yourself." },
  { channel: "Job offer", text: "A Telegram recruiter pays ₹150 for one task, then asks for ₹9,000 to unlock a premium set with guaranteed returns.", options: ["Deposit because the first payment was real", "Stop; early rewards can be bait", "Borrow money for the premium set", "Share bank login to speed it up"], answer: 1, explain: "Task scams often pay a small amount first to build trust, then demand increasingly large deposits." },
  { channel: "Customer care", text: "You found a support number in a sponsored search result. The agent asks you to install AnyDesk so they can process a refund.", options: ["Install it", "Give screen control but hide the PIN", "End the call and use in-app/official support", "Send a card photo"], answer: 2, explain: "A remote-access request during a refund is a major warning. Get support only from the official app, card or website." }
];

export const GUIDES = [
  { category: "Payments", icon: "▦", title: "UPI & QR scams", summary: "Understand collect requests, payment QR codes and why receiving money needs no PIN.", flags: ["QR to receive money", "Refund collect request", "Screen-share during payment"] },
  { category: "Impersonation", icon: "!", title: "Digital arrest", summary: "Fear-based calls impersonating police, customs or investigating agencies.", flags: ["Stay on video call", "Do not tell family", "Transfer a security deposit"] },
  { category: "Work", icon: "₹", title: "Task & fake job scams", summary: "Part-time offers that turn small rewards into escalating deposits.", flags: ["Guaranteed daily income", "Telegram-only recruiter", "Pay to unlock tasks"] },
  { category: "Shopping", icon: "◇", title: "Marketplace fraud", summary: "Advance payment, fake courier fees, false receipts and QR traps.", flags: ["Buyer sends QR", "Outside-platform deal", "Unverifiable receipt"] },
  { category: "Accounts", icon: "••", title: "KYC & account block phishing", summary: "Urgent messages designed to steal credentials through fake login pages.", flags: ["Account blocked today", "Unfamiliar link", "OTP or card details"] },
  { category: "Support", icon: "⌁", title: "Fake customer care", summary: "Fraudulent numbers and agents asking for remote access or payment.", flags: ["Install remote app", "Share screen", "Pay a support fee"] },
  { category: "Investment", icon: "↗", title: "Investment & crypto fraud", summary: "Fake dashboards, guaranteed profits and withdrawal fees.", flags: ["Guaranteed return", "Secret group tips", "Tax to release withdrawal"] },
  { category: "Delivery", icon: "▣", title: "Parcel & courier scams", summary: "Small address-update fees and false illegal-parcel threats.", flags: ["Customs threat", "Tiny redelivery payment", "Police transfer"] },
  { category: "Identity", icon: "◉", title: "SIM & identity misuse", summary: "Attempts to collect documents, selfies, OTPs or SIM access.", flags: ["Unexpected OTP", "SIM stops working", "Document + selfie demand"] }
];

export const LOCAL_REPORTS = [
  { identifier_type: "phone", identifier: "+91 ••••• 48217", report_type: "Fake customer care", description: "Caller requested a remote-access app for a refund.", report_count: 6, created_at: "2026-10-20" },
  { identifier_type: "website", identifier: "power-update-alert[.]example", report_type: "Phishing / KYC", description: "User-reported electricity disconnection payment link.", report_count: 3, created_at: "2026-10-18" },
  { identifier_type: "upi", identifier: "rewarddesk•••@bank", report_type: "Fake job / task", description: "Reported in an advance-fee task scheme.", report_count: 4, created_at: "2026-10-11" }
];

export const TRANSLATIONS = {
  en: { nav_home:"Overview",nav_checker:"Scam checker",nav_links:"Link inspector",nav_qr:"QR inspector",nav_screenshot:"Screenshot scan",nav_emergency:"Emergency mode",nav_community:"Community reports",nav_agreement:"Safety agreement",nav_simulator:"Scam simulator",nav_learn:"Knowledge hub",nav_tracker:"Risk tracker",nav_report:"Incident report",hero_title:"Stop the scam before you pay.",hero_subtitle:"Check suspicious messages, payment requests, links and QR codes. Get a clear risk score and the exact next step—without connecting your bank account.",check_now:"Check something now",lost_money:"I may have lost money" },
  hi: { nav_home:"सारांश",nav_checker:"स्कैम जाँच",nav_links:"लिंक जाँच",nav_qr:"QR जाँच",nav_screenshot:"स्क्रीनशॉट जाँच",nav_emergency:"आपातकाल",nav_community:"समुदाय रिपोर्ट",nav_agreement:"सुरक्षा समझौता",nav_simulator:"स्कैम अभ्यास",nav_learn:"ज्ञान केंद्र",nav_tracker:"जोखिम ट्रैकर",nav_report:"घटना रिपोर्ट",hero_title:"भुगतान से पहले स्कैम रोकें।",hero_subtitle:"संदिग्ध संदेश, भुगतान अनुरोध, लिंक और QR कोड जाँचें। बैंक खाता जोड़े बिना स्पष्ट जोखिम स्कोर और अगला कदम पाएँ।",check_now:"अभी जाँचें",lost_money:"शायद पैसे चले गए" },
  te: { nav_home:"అవలోకనం",nav_checker:"మోసం తనిఖీ",nav_links:"లింక్ తనిఖీ",nav_qr:"QR తనిఖీ",nav_screenshot:"స్క్రీన్‌షాట్ స్కాన్",nav_emergency:"అత్యవసర మోడ్",nav_community:"కమ్యూనిటీ రిపోర్టులు",nav_agreement:"భద్రతా ఒప్పందం",nav_simulator:"మోసం సిమ్యులేటర్",nav_learn:"జ్ఞాన కేంద్రం",nav_tracker:"రిస్క్ ట్రాకర్",nav_report:"సంఘటన రిపోర్ట్",hero_title:"చెల్లించే ముందే మోసాన్ని ఆపండి.",hero_subtitle:"అనుమానాస్పద సందేశాలు, పేమెంట్ రిక్వెస్ట్‌లు, లింకులు మరియు QR కోడ్‌లను తనిఖీ చేయండి. బ్యాంక్ ఖాతాను కనెక్ట్ చేయాల్సిన అవసరం లేదు.",check_now:"ఇప్పుడే తనిఖీ చేయండి",lost_money:"డబ్బు పోయి ఉండవచ్చు" },
  ta: { nav_home:"மேலோட்டம்",nav_checker:"மோசடி சோதனை",nav_links:"இணைப்பு சோதனை",nav_qr:"QR சோதனை",nav_screenshot:"திரைப்பிடிப்பு சோதனை",nav_emergency:"அவசர நிலை",nav_community:"சமூக அறிக்கைகள்",nav_agreement:"பாதுகாப்பு ஒப்பந்தம்",nav_simulator:"மோசடி பயிற்சி",nav_learn:"அறிவு மையம்",nav_tracker:"ஆபத்து கண்காணிப்பு",nav_report:"சம்பவ அறிக்கை",hero_title:"பணம் செலுத்தும் முன் மோசடியை நிறுத்துங்கள்.",hero_subtitle:"சந்தேகமான செய்திகள், கட்டண கோரிக்கைகள், இணைப்புகள் மற்றும் QR குறியீடுகளைச் சரிபார்க்கவும்.",check_now:"இப்போது சரிபார்க்கவும்",lost_money:"பணம் இழந்திருக்கலாம்" },
  kn: { nav_home:"ಅವಲೋಕನ",nav_checker:"ವಂಚನೆ ಪರಿಶೀಲನೆ",nav_links:"ಲಿಂಕ್ ಪರಿಶೀಲನೆ",nav_qr:"QR ಪರಿಶೀಲನೆ",nav_screenshot:"ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಸ್ಕ್ಯಾನ್",nav_emergency:"ತುರ್ತು ಮೋಡ್",nav_community:"ಸಮುದಾಯ ವರದಿಗಳು",nav_agreement:"ಸುರಕ್ಷತಾ ಒಪ್ಪಂದ",nav_simulator:"ವಂಚನೆ ಅಭ್ಯಾಸ",nav_learn:"ಜ್ಞಾನ ಕೇಂದ್ರ",nav_tracker:"ಅಪಾಯ ಟ್ರ್ಯಾಕರ್",nav_report:"ಘಟನೆ ವರದಿ",hero_title:"ಪಾವತಿಸುವ ಮೊದಲು ವಂಚನೆಯನ್ನು ನಿಲ್ಲಿಸಿ.",hero_subtitle:"ಅನುಮಾನಾಸ್ಪದ ಸಂದೇಶಗಳು, ಪಾವತಿ ವಿನಂತಿಗಳು, ಲಿಂಕ್‌ಗಳು ಮತ್ತು QR ಕೋಡ್‌ಗಳನ್ನು ಪರಿಶೀಲಿಸಿ.",check_now:"ಈಗ ಪರಿಶೀಲಿಸಿ",lost_money:"ಹಣ ಕಳೆದುಹೋಗಿರಬಹುದು" }
};
