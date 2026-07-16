### S01_Greeting_Only
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`

### S02_Greeting_Then_Tech
- **Attacker**: "hello"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "update your kyc"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S03_Greeting_Greeting
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "hello"
  - **Bot**: `??`

### S04_Tech_First
- **Attacker**: "update your kyc"
  - **Bot**: `??`

### S05_OffTopic_First
- **Attacker**: "how are you doing"
  - **Bot**: `??`

### S06_Greeting_Then_OffTopic
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "how are you doing"
  - **Bot**: `??`

### S07_Greeting_Tech_Tech
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "update kyc"
  - **Bot**: `[LLM_RESPONSE: kyc]`
- **Attacker**: "here is the apk"
  - **Bot**: `okay I will see it ..`

### S08_Greeting_Tech_OffTopic
- **Attacker**: "hey"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "click this link"
  - **Bot**: `[LLM_RESPONSE: delay]`
- **Attacker**: "how is the weather"
  - **Bot**: `??`

### S09_Tech_Then_Tech
- **Attacker**: "kyc blocked"
  - **Bot**: `??`
- **Attacker**: "install this apk"
  - **Bot**: `okay I will see it ..`

### S10_OffTopic_Then_Tech
- **Attacker**: "what is your name"
  - **Bot**: `??`
- **Attacker**: "sbi account blocked"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S11_Greeting_Then_Thanks
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "ok"
  - **Bot**: `[LLM_RESPONSE: thanks]`

### S12_Fallback_Limit_Test
- **Attacker**: "how are you"
  - **Bot**: `??`
- **Attacker**: "tell me"
  - **Bot**: `??`
- **Attacker**: "who are you"
  - **Bot**: `<Response></Response> (IGNORED)`
- **Attacker**: "stop"
  - **Bot**: `<Response></Response> (IGNORED)`

### S13_Greeting_Then_FallbackLimit
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "what"
  - **Bot**: `??`
- **Attacker**: "who"
  - **Bot**: `??`
- **Attacker**: "tell me"
  - **Bot**: `<Response></Response> (IGNORED)`
- **Attacker**: "please"
  - **Bot**: `<Response></Response> (IGNORED)`

### S14_Greeting_Then_Pdf
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "open this pdf"
  - **Bot**: `okay I will see it ..`

### S15_Greeting_Then_Apk
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "download apk"
  - **Bot**: `okay I will see it ..`

### S16_Start_Then_Sbi
- **Attacker**: "start"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "sbi details"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S17_Hola_Then_Yono
- **Attacker**: "hola"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "yono app"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S18_GoodMorning_Then_Blocked
- **Attacker**: "good morning"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "account is blocked"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S19_Greeting_Then_Url
- **Attacker**: "hey"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "https://malicious.com"
  - **Bot**: `okay I will see it ..`

### S20_Greeting_Thanks_Tech
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "thank you"
  - **Bot**: `[LLM_RESPONSE: thanks]`
- **Attacker**: "update kyc"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S21_Url_First
- **Attacker**: "https://malicious.com"
  - **Bot**: `??`

### S22_Pdf_First
- **Attacker**: "open pdf"
  - **Bot**: `??`

### S23_Apk_First
- **Attacker**: "install apk"
  - **Bot**: `??`

### S24_Thanks_First
- **Attacker**: "ok"
  - **Bot**: `??`

### S25_Greeting_OffTopic_Tech
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "who are you"
  - **Bot**: `??`
- **Attacker**: "sbi account"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S26_OffTopic_Greeting_Tech
- **Attacker**: "what"
  - **Bot**: `??`
- **Attacker**: "hi"
  - **Bot**: `??`
- **Attacker**: "sbi kyc"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S27_EmptyMessage
- **Attacker**: ""
  - **Bot**: `[LLM_RESPONSE: greeting]`

### S28_Greeting_EmptyMessage
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: ""
  - **Bot**: `??`

### S29_Multiple_Greetings
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "hello"
  - **Bot**: `??`
- **Attacker**: "hey"
  - **Bot**: `??`
- **Attacker**: "start"
  - **Bot**: `<Response></Response> (IGNORED)`

### S30_Complex_Technical
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "sbi blocked"
  - **Bot**: `[LLM_RESPONSE: kyc]`
- **Attacker**: "download apk"
  - **Bot**: `okay I will see it ..`
- **Attacker**: "thank you"
  - **Bot**: `[LLM_RESPONSE: thanks]`
- **Attacker**: "link"
  - **Bot**: `[LLM_RESPONSE: delay]`

### S31_Greeting_Then_Unknown_Then_Tech
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "unknown"
  - **Bot**: `??`
- **Attacker**: "kyc"
  - **Bot**: `[LLM_RESPONSE: kyc]`

### S32_Long_OffTopic
- **Attacker**: "hi"
  - **Bot**: `[LLM_RESPONSE: greeting]`
- **Attacker**: "this is a very long message that does not contain any keywords at all"
  - **Bot**: `??`
