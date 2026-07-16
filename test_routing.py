import os, sys
sys.path.insert(0, os.path.abspath('.'))
import src.lures.reply_engine
src.lures.reply_engine.generate_llm_reply = lambda m, b, s: f'[LLM_RESPONSE: {b}]'

scenarios = [
    ('S01_Greeting_Only', ['hi']),
    ('S02_Greeting_Then_Tech', ['hello', 'update your kyc']),
    ('S03_Greeting_Greeting', ['hi', 'hello']),
    ('S04_Tech_First', ['update your kyc']),
    ('S05_OffTopic_First', ['how are you doing']),
    ('S06_Greeting_Then_OffTopic', ['hi', 'how are you doing']),
    ('S07_Greeting_Tech_Tech', ['hi', 'update kyc', 'here is the apk']),
    ('S08_Greeting_Tech_OffTopic', ['hey', 'click this link', 'how is the weather']),
    ('S09_Tech_Then_Tech', ['kyc blocked', 'install this apk']),
    ('S10_OffTopic_Then_Tech', ['what is your name', 'sbi account blocked']),
    ('S11_Greeting_Then_Thanks', ['hi', 'ok']),
    ('S12_Fallback_Limit_Test', ['how are you', 'tell me', 'who are you', 'stop']),
    ('S13_Greeting_Then_FallbackLimit', ['hi', 'what', 'who', 'tell me', 'please']),
    ('S14_Greeting_Then_Pdf', ['hi', 'open this pdf']),
    ('S15_Greeting_Then_Apk', ['hi', 'download apk']),
    ('S16_Start_Then_Sbi', ['start', 'sbi details']),
    ('S17_Hola_Then_Yono', ['hola', 'yono app']),
    ('S18_GoodMorning_Then_Blocked', ['good morning', 'account is blocked']),
    ('S19_Greeting_Then_Url', ['hey', 'https://malicious.com']),
    ('S20_Greeting_Thanks_Tech', ['hi', 'thank you', 'update kyc']),
    ('S21_Url_First', ['https://malicious.com']),
    ('S22_Pdf_First', ['open pdf']),
    ('S23_Apk_First', ['install apk']),
    ('S24_Thanks_First', ['ok']),
    ('S25_Greeting_OffTopic_Tech', ['hi', 'who are you', 'sbi account']),
    ('S26_OffTopic_Greeting_Tech', ['what', 'hi', 'sbi kyc']),
    ('S27_EmptyMessage', ['']),
    ('S28_Greeting_EmptyMessage', ['hi', '']),
    ('S29_Multiple_Greetings', ['hi', 'hello', 'hey', 'start']),
    ('S30_Complex_Technical', ['hi', 'sbi blocked', 'download apk', 'thank you', 'link']),
    ('S31_Greeting_Then_Unknown_Then_Tech', ['hi', 'unknown', 'kyc']),
    ('S32_Long_OffTopic', ['hi', 'this is a very long message that does not contain any keywords at all'])
]

results = []
for name, msgs in scenarios:
    src.lures.reply_engine._history.clear()
    src.lures.reply_engine._fallback_counts.clear()
    
    res = f'### {name}\n'
    for i, msg in enumerate(msgs):
        sender_id = f'test_{name}'
        
        branch = None
        if 'http' in msg: branch = 'url'
        if 'apk' in msg: branch = 'media_apk'
        if 'pdf' in msg: branch = 'media_pdf'
        
        reply = src.lures.reply_engine.get_lure_reply(msg, branch=branch, sender_id=sender_id)
        if reply == '': reply = '<Response></Response> (IGNORED)'
        res += f'- **Attacker**: \"{msg}\"\n  - **Bot**: `{reply}`\n'
    results.append(res)

with open('scenarios_output.md', 'w') as f:
    f.write('\n'.join(results))
print('Output written to scenarios_output.md')
