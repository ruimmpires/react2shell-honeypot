import logging
import random
import string
import re
from flask import Flask, request, Response
from pythonjsonlogger import jsonlogger

app = Flask(__name__)

# --- LOGGING CONFIGURATION ---
logger = logging.getLogger()
logHandler = logging.FileHandler('/var/log/honeypot.json')
# Custom JSON formatter
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s', rename_fields={'levelname': 'log_level', 'asctime': '@timestamp'})
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

# Fake System Identity
FAKE_USER = "nextjs"
FAKE_UID = "1001"
FAKE_HOSTNAME = "ip-10-0-4-23"

def defang_url(text):
    """Replaces http:// with hxxp:// to make logs safer."""
    return text.replace("http:", "hxxp:").replace("https:", "hxxps:")

def generate_fake_digest():
    """Generates a random digest to mimic React error codes."""
    return ''.join(random.choices(string.hexdigits, k=32)).lower()

def emulate_shell_output(command):
    cmd = command.lower()
    if "whoami" in cmd:
        return f"{FAKE_USER}\n"
    if "id" in cmd:
        return f"uid={FAKE_UID}({FAKE_USER}) gid={FAKE_UID}({FAKE_USER}) groups={FAKE_UID}({FAKE_USER})\n"
    if "uname" in cmd:
        return f"Linux {FAKE_HOSTNAME} 5.15.0-1053-aws #58-Ubuntu SMP Fri Dec 13 14:00:00 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
    if "wget" in cmd or "curl" in cmd:
        return "100%[===================>] 4.20K  --.-KB/s    in 0s      \n\n2025-12-16 10:00:00 (100 MB/s) - 'malware.sh' saved [4200/4200]\n"
    return ""

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'HEAD'])
def catch_all(path):
    src_ip = request.remote_addr
    headers = dict(request.headers)
    body = request.get_data(as_text=True)



    # STAGE 2: DETECT RCE
    rce_pattern = re.compile(r'(wget|curl|whoami|id|uname|bash|sh)\b', re.IGNORECASE)
    match = rce_pattern.search(body)
    
    if match:
        command_detected = match.group(0)
        log_snippet = defang_url(body[max(0, match.start()-10):min(len(body), match.end()+100)])
        
        # Log CRITICAL alert
        logger.critical("RCE Attempt Detected", extra={
            "event_id": "RCE_ATTEMPT_DETECTED",
            "threat_intel": {
                "vulnerability": "CVE-2025-55182",
                "attack_stage": 2,
                "classification": "Malware Dropper" if command_detected in ['wget','curl'] else "Reconnaissance",
                "command_detected": command_detected
            },
            "network": {"src_ip": src_ip},
            "payload": {
                "raw_snippet": log_snippet,
                "ioc_extracted": log_snippet # Simplified extraction for demo
            }
        })

        fake_output = emulate_shell_output(command_detected)
        return Response(fake_output, status=200, mimetype='text/plain')

    # STAGE 1: DETECT PROBE
    if '$1:a:a' in body:
        logger.info("Probe Detected", extra={
            "event_id": "STAGE_1_PROBE",
            "network": {"src_ip": src_ip},
            "http": {"headers": headers}
        })
        fake_digest = generate_fake_digest()
        error_content = f'E{{"digest":"{fake_digest}"}}'
        return Response(error_content, status=500, mimetype='text/plain; charset=utf-8')


    return "Not Found", 404
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
