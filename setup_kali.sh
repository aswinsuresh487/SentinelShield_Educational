#!/bin/bash

# SentinelShield Educational Version - Kali Linux Setup Script

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    SentinelShield Educational WAF - Kali Linux Setup     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Detected Environment: Kali Linux in VirtualBox"
echo ""

# Step 1: Create directories
echo "[1/7] Creating project structure..."
mkdir -p logs reports screenshots tests docs
echo "      ✓ Directories created"

# Step 2: Update package manager
echo "[2/7] Updating package manager..."
sudo apt-get update -qq
echo "      ✓ Package manager updated"

# Step 3: Install dependencies (most should already be in Kali)
echo "[3/7] Installing system dependencies..."
sudo apt-get install -y python3 python3-pip python3-venv docker.io curl jq -qq
echo "      ✓ Dependencies installed"

# Step 4: Configure Docker
echo "[4/7] Configuring Docker..."

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group (to avoid sudo)
sudo usermod -aG docker $USER

echo "      ✓ Docker configured"
echo "      ℹ Note: You may need to log out and back in for Docker group to take effect"
echo "      ℹ Or run: newgrp docker"

# Step 5: Create Python virtual environment
echo "[5/7] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "      ✓ Virtual environment created"

# Step 6: Install Python packages
echo "[6/7] Installing Python packages..."
pip install --quiet --upgrade pip
pip install --quiet flask requests
echo "      ✓ Python packages installed"

# Step 7: Setup DVWA
echo "[7/7] Setting up DVWA (target application)..."

# Check if DVWA already exists
if docker ps -a --format '{{.Names}}' | grep -q '^dvwa$'; then
    echo "      ℹ DVWA container already exists"
    
    # Check if it's running
    if docker ps --format '{{.Names}}' | grep -q '^dvwa$'; then
        echo "      ✓ DVWA is already running"
    else
        echo "      → Starting existing DVWA container..."
        docker start dvwa
        echo "      ✓ DVWA started"
    fi
else
    echo "      → Pulling DVWA image (this may take 2-3 minutes)..."
    docker pull vulnerables/web-dvwa
    
    echo "      → Starting DVWA container..."
    docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
    
    echo "      → Waiting for DVWA to initialize (20 seconds)..."
    sleep 20
    echo "      ✓ DVWA is ready"
fi

# Verify DVWA is accessible
echo ""
echo "      → Testing DVWA accessibility..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "200\|302"; then
    echo "      ✓ DVWA is accessible at http://localhost:8080"
else
    echo "      ⚠ DVWA might still be starting, wait 30 more seconds"
fi

# Create example test file
echo ""
echo "Creating example documentation templates..."
cat > tests/manual_tests.md << 'EOF'
# SentinelShield Manual Testing Documentation

**Project**: SentinelShield Educational WAF
**Environment**: Kali Linux (VirtualBox)
**Author**: [Your Name]
**Date**: [Today's Date]

---

## Test 1: Normal Request - Homepage

**Command:**
```bash
curl "http://localhost:5000/index.php"
```

**Expected Result:** ALLOWED (request should pass through)

**Actual Result:** 
[Fill in after testing - Did it work? What was the response?]

**Analysis:** 
[Why should this be allowed? What makes it "clean"?]

---

## Test 2: SQL Injection - OR Clause

**Command:**
```bash
curl "http://localhost:5000/user.php?id=1' OR '1'='1"
```

**Expected Result:** BLOCKED (403 Forbidden)

**Actual Result:** 
[Fill in after testing]

**Attack Type:** SQL Injection

**Why Detected:** 
[Explain which pattern matched and why]

**Real-world Impact:** 
[What could an attacker do with this?]

**Detection Rule:** 
[Which regex pattern caught this?]

---

## Test 3: XSS - Script Tag Injection

**Command:**
```bash
curl "http://localhost:5000/search.php?q=<script>alert('XSS')</script>"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 4: Path Traversal - /etc/passwd

**Command:**
```bash
curl "http://localhost:5000/file.php?page=../../../../etc/passwd"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 5: Command Injection - Semicolon

**Command:**
```bash
curl "http://localhost:5000/ping.php?host=127.0.0.1; cat /etc/passwd"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 6: [Add Your Own Test]

**Command:**
```bash
[Your curl command]
```

**Expected Result:** [BLOCKED or ALLOWED]

**Actual Result:** [Your observation]

**Analysis:** [Your explanation]

---

## Summary

**Total Tests Performed:** [Number]
**Blocked Correctly:** [Number]
**Allowed Correctly:** [Number]
**False Positives:** [Number - legitimate requests blocked]
**False Negatives:** [Number - attacks that got through]

**Key Findings:**
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

**Improvements Needed:**
1. [Improvement 1]
2. [Improvement 2]
3. [Improvement 3]
EOF

cat > docs/project_journal.md << 'EOF'
# SentinelShield Project Journal

**Project**: Web Application Firewall (WAF) Development
**Environment**: Kali Linux on VirtualBox
**Author**: [Your Name]
**Internship**: [Company Name]
**Duration**: [Start Date] to [End Date]

---

## Week 1: Project Setup & Understanding

### Day 1: Environment Setup
**Date**: [Date]

**Activities:**
- Set up Kali Linux environment
- Installed Docker and DVWA
- Created Python virtual environment
- Reviewed project requirements

**What I Learned:**
- [Learning point 1]
- [Learning point 2]

**Challenges:**
- [Challenge 1 and how I solved it]

---

### Day 2: Understanding HTTP & Attacks
**Date**: [Date]

**Activities:**
- Studied HTTP request structure
- Researched SQL injection attacks
- Researched XSS attacks
- Performed manual testing with curl

**Key Concepts Learned:**
1. **HTTP Requests contain:**
   - Method (GET, POST)
   - Path (/index.php)
   - Query parameters (?id=1)
   - Headers (User-Agent, etc.)

2. **SQL Injection:**
   - [Your notes on what it is and how it works]

3. **XSS (Cross-Site Scripting):**
   - [Your notes]

**Examples I Tested:**
- [Example 1 with result]
- [Example 2 with result]

---

### Day 3: Building the WAF Core
**Date**: [Date]

**Activities:**
- Wrote simple_waf.py
- Implemented detection rules
- Added logging functionality

**Code Sections I Implemented:**
1. **Detection Rules (Lines X-Y)**
   - Purpose: [Explain]
   - How it works: [Explain]

2. **Inspection Function (Lines X-Y)**
   - Purpose: [Explain]
   - How it works: [Explain]

**Problems Encountered:**
- **Problem**: [Description]
  - **Solution**: [How you fixed it]

---

### Day 4: Testing Phase
**Date**: [Date]

**Manual Testing:**
- Performed 15 manual tests
- Documented each test
- Analyzed results

**Key Findings:**
- Detection rate: [X%]
- False positives: [Number and examples]
- False negatives: [Number and examples]

**Automated Testing:**
- Created automated_tests.py
- Ran 12 automated test cases
- Results: [Pass/Fail summary]

---

### Day 5: Analysis & Reporting
**Date**: [Date]

**Activities:**
- Analyzed logs
- Generated HTML report
- Documented findings

**Statistics:**
- Total requests: [X]
- Blocked: [Y]
- Most common attack: [Type]

---

## Week 2: Improvements & Documentation

### Day 1-2: Adding Custom Rules
**Date**: [Date]

**New Rules I Added:**

```python
# Rule 1: [Description]
'attack_type': [
    r"pattern",  # Explanation
]
```

**Why I Added These:**
- [Reasoning for Rule 1]
- [Reasoning for Rule 2]

**Testing My Rules:**
- [Test results showing they work]

---

### Day 3: Documentation
**Date**: [Date]

**Documents Created:**
- Technical report
- Project journal (this document)
- Test documentation
- Screenshots

---

### Day 4: Final Testing & Refinement
**Date**: [Date]

**Final Tests:**
- [Summary of final testing]

**Final Statistics:**
- Detection rate: [X%]
- Total tests: [Y]

---

## Key Learnings

### Technical Skills Gained:
1. [Skill 1]
2. [Skill 2]
3. [Skill 3]

### Security Concepts Understood:
1. [Concept 1]
2. [Concept 2]
3. [Concept 3]

### Tools Mastered:
1. Flask framework
2. Regex pattern matching
3. Docker containers
4. Python logging

---

## Challenges Overcome

### Challenge 1: [Title]
**Problem**: [Description]
**What I Tried**: [Attempts]
**Solution**: [Final solution]
**What I Learned**: [Lesson]

### Challenge 2: [Title]
[Same format]

---

## Future Improvements

If I had more time, I would:
1. [Improvement 1]
2. [Improvement 2]
3. [Improvement 3]

---

## Reflection

### What Went Well:
- [Point 1]
- [Point 2]

### What Could Be Better:
- [Point 1]
- [Point 2]

### Most Valuable Learning:
[Your reflection on the most important thing you learned]

---

## Conclusion

This project taught me [summary of key learnings]. I now understand [what you understand]. The most challenging part was [challenge], which I overcame by [solution].
EOF

echo "      ✓ Documentation templates created"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   SETUP COMPLETE!                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "🎉 Your Kali Linux environment is ready!"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "QUICK START GUIDE"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "1️⃣  Verify DVWA is accessible:"
echo "   → Open Firefox: http://localhost:8080"
echo "   → Login: admin / password"
echo "   → Set security level to LOW"
echo ""
echo "2️⃣  Start the WAF (in this terminal):"
echo "   → source venv/bin/activate"
echo "   → python3 simple_waf.py"
echo ""
echo "3️⃣  Test manually (open NEW terminal):"
echo "   → cd ~/SentinelShield_Educational"
echo "   → curl \"http://localhost:5000/waf/status\""
echo "   → curl \"http://localhost:5000/test.php?id=1' OR '1'='1\""
echo ""
echo "4️⃣  Run automated tests (while WAF is running):"
echo "   → cd ~/SentinelShield_Educational"
echo "   → source venv/bin/activate"
echo "   → python3 automated_tests.py"
echo ""
echo "5️⃣  Generate report:"
echo "   → python3 generate_report.py"
echo "   → firefox reports/dashboard.html"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "KALI-SPECIFIC TIPS"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📸 Taking Screenshots in Kali:"
echo "   → Press 'Print Screen' key"
echo "   → Or: Applications → Screenshot"
echo "   → Save to screenshots/ folder"
echo ""
echo "🐳 Docker Commands:"
echo "   → View containers: docker ps -a"
echo "   → Stop DVWA: docker stop dvwa"
echo "   → Start DVWA: docker start dvwa"
echo "   → Remove DVWA: docker rm -f dvwa"
echo ""
echo "🔍 Useful Kali Tools (for advanced testing):"
echo "   → sqlmap: SQL injection testing"
echo "   → nikto: Web vulnerability scanner"
echo "   → burpsuite: HTTP proxy/interceptor"
echo ""
echo "💡 VirtualBox Tips:"
echo "   → Take snapshot before major changes"
echo "   → Allocate at least 2GB RAM to VM"
echo "   → Use NAT or Bridged network mode"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Next: Follow the complete guide to build your WAF step-by-step!"
echo "Happy learning! 🛡️"
echo ""

# Remind about docker group
echo "⚠️  IMPORTANT: If you get Docker permission errors:"
echo "   Run: newgrp docker"
echo "   Or: Log out and log back in"
echo ""
