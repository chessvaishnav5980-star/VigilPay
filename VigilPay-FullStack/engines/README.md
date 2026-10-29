# Optional Java and C++ engines

VigilPay’s production website uses JavaScript in the browser, Node.js at the web edge and an optional Python FastAPI service. The Java and C++ folders provide dependency-free offline versions of the scoring concept for demonstrations, school exhibits or later native-app work. They are not downloaded by visitors and do not slow the website.

## Java

```bash
javac engines/java/VigilPayRiskEngine.java
java -cp engines/java VigilPayRiskEngine "Share your OTP immediately"
```

## C++

```bash
g++ -std=c++17 -O2 engines/cpp/risk_engine.cpp -o risk_engine
printf '%s' 'Install AnyDesk immediately' | ./risk_engine
```

Both programs print a small JSON result and make no network request.
