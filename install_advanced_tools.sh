#!/bin/bash

# Install all advanced security tools
echo "🚀 Installing Advanced Security Arsenal..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Core dependencies
echo -e "${YELLOW}[1/5] Installing core dependencies...${NC}"
sudo apt-get update -qq
sudo apt-get install -y python3-pip python3-venv golang-go git curl wget pipx

# Set up Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
mkdir -p $GOPATH/bin

# Go tools - Advanced Arsenal
echo -e "${YELLOW}[2/5] Installing Go-based security tools...${NC}"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/sa7mon/s3scanner@latest
go install github.com/michenriksen/aquatone@latest
go install github.com/jaeles-project/gospider@latest

# Python tools with virtual environment
echo -e "${YELLOW}[3/5] Installing Python security tools...${NC}"
python3 -m venv ~/security_venv
source ~/security_venv/bin/activate
pip install trufflehog arjun requests beautifulsoup4 lxml

# Alternative: Use pipx for system-wide Python tools
pipx install trufflehog || pip3 install trufflehog --break-system-packages

# Clone advanced tools - ULTIMATE ARSENAL
echo -e "${YELLOW}[4/5] Cloning advanced security tools...${NC}"
sudo mkdir -p /opt

# Remove existing directories and clone fresh
[ -d "/opt/XSStrike" ] && sudo rm -rf /opt/XSStrike
[ -d "/opt/SecretFinder" ] && sudo rm -rf /opt/SecretFinder
[ -d "/opt/OpenRedireX" ] && sudo rm -rf /opt/OpenRedireX
[ -d "/opt/dorks-eye" ] && sudo rm -rf /opt/dorks-eye
[ -d "/opt/FavFreak" ] && sudo rm -rf /opt/FavFreak
[ -d "/opt/commix" ] && sudo rm -rf /opt/commix
[ -d "/opt/LazyXSS" ] && sudo rm -rf /opt/LazyXSS
[ -d "/opt/LFImap" ] && sudo rm -rf /opt/LFImap

# XSS and Injection Tools
sudo git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike
sudo git clone https://github.com/commixproject/commix.git /opt/commix
sudo git clone https://github.com/rezasp/LazyXSS.git /opt/LazyXSS
sudo git clone https://github.com/hansmach1ne/LFImap.git /opt/LFImap

# Reconnaissance Tools
sudo git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
sudo git clone https://github.com/devanshbatham/OpenRedireX.git /opt/OpenRedireX
sudo git clone https://github.com/BullsEye0/dorks-eye.git /opt/dorks-eye
sudo git clone https://github.com/devanshbatham/FavFreak.git /opt/FavFreak

# Install Python dependencies for cloned tools
echo -e "${YELLOW}[5/5] Installing tool dependencies...${NC}"
cd /opt/XSStrike && sudo pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
cd /opt/SecretFinder && sudo pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
cd /opt/OpenRedireX && sudo pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true

# Copy binaries to PATH
sudo cp $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || true

# Make Python tools executable
sudo chmod +x /opt/XSStrike/xsstrike.py
sudo chmod +x /opt/SecretFinder/SecretFinder.py
sudo chmod +x /opt/OpenRedireX/openredirex.py

# Create wrapper scripts for ALL advanced tools
sudo tee /usr/local/bin/xsstrike > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/XSStrike/xsstrike.py "$@"
EOF

sudo tee /usr/local/bin/secretfinder > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/SecretFinder/SecretFinder.py "$@"
EOF

sudo tee /usr/local/bin/openredirex > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/OpenRedireX/openredirex.py "$@"
EOF

sudo tee /usr/local/bin/commix > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/commix/commix.py "$@"
EOF

sudo tee /usr/local/bin/lazyxss > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/LazyXSS/lazyxss.py "$@"
EOF

sudo tee /usr/local/bin/lfimap > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/LFImap/lfimap.py "$@"
EOF

sudo tee /usr/local/bin/dorks-eye > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/dorks-eye/dorks-eye.py "$@"
EOF

sudo tee /usr/local/bin/favfreak > /dev/null << 'EOF'
#!/bin/bash
python3 /opt/FavFreak/favfreak.py "$@"
EOF

# Make all wrapper scripts executable
sudo chmod +x /usr/local/bin/xsstrike
sudo chmod +x /usr/local/bin/secretfinder
sudo chmod +x /usr/local/bin/openredirex
sudo chmod +x /usr/local/bin/commix
sudo chmod +x /usr/local/bin/lazyxss
sudo chmod +x /usr/local/bin/lfimap
sudo chmod +x /usr/local/bin/dorks-eye
sudo chmod +x /usr/local/bin/favfreak

# Update Nuclei templates
nuclei -update-templates -silent 2>/dev/null || true

echo -e "${GREEN}✅ Advanced security arsenal installed successfully!${NC}"
echo ""
echo -e "${GREEN}Installed tools:${NC}"
echo "• Subfinder, HTTPx, Nuclei, Katana (ProjectDiscovery)"
echo "• ffuf, GAU, Waybackurls"
echo "• XSStrike, SecretFinder, OpenRedireX"
echo "• TruffleHog, Arjun"
echo ""
echo -e "${YELLOW}Usage examples:${NC}"
echo "• xsstrike -u https://target.com"
echo "• secretfinder -i https://target.com/app.js"
echo "• openredirex -u https://target.com"
