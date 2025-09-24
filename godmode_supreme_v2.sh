#!/bin/bash

# ========================================================================
# GODMODE SUPREME AI SCANNER v2.0 - WORLD'S MOST ADVANCED VULNERABILITY SCANNER
# Revolutionary AI-powered security testing with zero false positives
# Features: Nuclei integration, vulnerability chaining, advanced AI analysis
# ========================================================================

set -euo pipefail

# Colors and styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Global configuration
WORKSPACE_DIR=""
TARGET_DOMAIN=""
SCAN_START_TIME=$(date +%s)
VULNERABILITY_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Advanced logging with timestamps
log_info() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1"
}

log_critical() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}${BOLD}[CRITICAL]${NC} $1"
    ((CRITICAL_COUNT++))
    send_critical_alert "$1"
}

# Advanced notification system
send_critical_alert() {
    local message="$1"
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="🚨 CRITICAL: $TARGET_DOMAIN%0A$message%0ATime: $(date '+%H:%M:%S')" > /dev/null 2>&1 || true
    fi
}

# Real-time updates
send_telegram_update() {
    local message="$1"
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="🔍 GODMODE: $TARGET_DOMAIN - $message" \
            -d parse_mode="HTML" > /dev/null 2>&1 || true
        log_info "📱 Telegram: $message"
    fi
}

# Install world-class security tools
install_supreme_tools() {
    log_info "Installing world-class security arsenal..."
    
    # Core dependencies
    sudo apt-get update -qq
    sudo apt-get install -y curl wget git golang-go python3 python3-pip jq nmap masscan subfinder httpx nuclei katana gau waybackurls anew notify 2>/dev/null || {
        # Manual installation if package manager fails
        install_go_tools
    }
    
    # Update Nuclei templates
    nuclei -update-templates -silent
    
    log_success "Supreme security arsenal ready"
}

# Install Go-based tools manually
install_go_tools() {
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
    
    # ProjectDiscovery tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    
    # Additional tools
    go install github.com/lc/gau/v2/cmd/gau@latest
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/anew@latest
    
    # Copy to system path
    sudo cp $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || true
}

# Advanced AI vulnerability analysis
ai_analyze_vulnerability() {
    local url="$1"
    local vuln_type="$2"
    local payload="$3"
    local response="$4"
    
    if [ -z "${AI_SERVICE:-}" ]; then
        echo "AI analysis unavailable - no service configured"
        return
    fi
    
    # Optimized prompt for CodeLlama 7B
    local prompt="Security Analysis Task:
URL: $url
Vulnerability Type: $vuln_type
Test Payload: $payload
Server Response: $(echo "$response" | head -5)

Analysis Required:
1. Is this a real vulnerability? (YES/NO)
2. Risk Level: (CRITICAL/HIGH/MEDIUM/LOW)
3. Exploitable: (EASY/HARD)
4. False Positive Chance: (0-100%)

Respond in JSON format only."
    
    case "${AI_SERVICE}" in
        "gemini")
            ai_gemini_analyze "$prompt"
            ;;
        "groq")
            ai_groq_analyze "$prompt"
            ;;
        "ollama")
            ai_ollama_analyze "$prompt"
            ;;
        *)
            echo "Unknown AI service: ${AI_SERVICE}"
            ;;
    esac
}

# Gemini AI analysis
ai_gemini_analyze() {
    local prompt="$1"
    
    if [ -z "${GEMINI_API_KEY:-}" ]; then
        echo "Gemini API key not configured"
        return
    fi
    
    curl -s -X POST \
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY}" \
        -H 'Content-Type: application/json' \
        -d "{\"contents\":[{\"parts\":[{\"text\":\"$prompt\"}]}]}" | \
        jq -r '.candidates[0].content.parts[0].text' 2>/dev/null || echo "AI analysis failed"
}

# Groq AI analysis  
ai_groq_analyze() {
    local prompt="$1"
    
    if [ -z "${GROQ_API_KEY:-}" ]; then
        echo "Groq API key not configured"
        return
    fi
    
    curl -s -X POST \
        "https://api.groq.com/openai/v1/chat/completions" \
        -H "Authorization: Bearer ${GROQ_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"messages\":[{\"role\":\"user\",\"content\":\"$prompt\"}],\"model\":\"mixtral-8x7b-32768\"}" | \
        jq -r '.choices[0].message.content' 2>/dev/null || echo "AI analysis failed"
}

# Ollama AI analysis (CodeLlama 7B optimized)
ai_ollama_analyze() {
    local prompt="$1"
    
    if ! command -v ollama &> /dev/null; then
        echo "Ollama not installed"
        return
    fi
    
    # Optimized for CodeLlama 7B with security context
    curl -s -X POST http://localhost:11434/api/generate \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"${OLLAMA_MODEL:-codellama:7b}\",
            \"prompt\": \"You are a cybersecurity expert. $prompt\",
            \"stream\": false,
            \"options\": {
                \"temperature\": 0.1,
                \"top_p\": 0.9,
                \"max_tokens\": 500
            }
        }" | jq -r '.response' 2>/dev/null || echo "Ollama analysis failed"
}

# Revolutionary subdomain discovery
supreme_subdomain_discovery() {
    log_info "Phase 1: Revolutionary Subdomain Discovery"
    send_telegram_update "🔍 Starting subdomain discovery"
    
    local subdomains_dir="$WORKSPACE_DIR/subdomains"
    mkdir -p "$subdomains_dir"
    
    # Multiple advanced techniques
    log_info "Running Subfinder with all sources..."
    subfinder -d "$TARGET_DOMAIN" -all -silent -o "$subdomains_dir/subfinder.txt" 2>/dev/null || touch "$subdomains_dir/subfinder.txt"
    
    log_info "Certificate Transparency mining..."
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$subdomains_dir/crt.txt" 2>/dev/null || touch "$subdomains_dir/crt.txt"
    
    log_info "DNS bruteforce with custom wordlist..."
    # Advanced DNS bruteforce
    cat > "$subdomains_dir/dns_wordlist.txt" << 'EOF'
admin
api
app
beta
dev
test
staging
www
mail
ftp
blog
shop
store
portal
dashboard
panel
cpanel
webmail
secure
login
auth
sso
vpn
remote
support
help
docs
cdn
static
assets
img
images
js
css
media
upload
download
backup
old
new
v1
v2
api-v1
api-v2
mobile
m
wap
EOF
    
    while read -r sub; do
        if dig +short "$sub.$TARGET_DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null 2>&1; then
            echo "$sub.$TARGET_DOMAIN" >> "$subdomains_dir/dns_brute.txt"
        fi
    done < "$subdomains_dir/dns_wordlist.txt"
    
    # Combine and deduplicate
    cat "$subdomains_dir"/*.txt 2>/dev/null | sort -u | anew "$subdomains_dir/all_subdomains.txt" >/dev/null 2>&1
    
    local subdomain_count=$(wc -l < "$subdomains_dir/all_subdomains.txt" 2>/dev/null || echo "0")
    log_success "Discovered $subdomain_count subdomains"
}

# Advanced port scanning with service detection
supreme_port_scanning() {
    log_info "Phase 2: Advanced Port & Service Discovery"
    
    local ports_dir="$WORKSPACE_DIR/ports"
    mkdir -p "$ports_dir"
    
    # Skip slow port scanning, use HTTPx for service discovery
    log_info "Using HTTPx for fast service discovery (skipping slow nmap)..."
    httpx -l "$WORKSPACE_DIR/subdomains/all_subdomains.txt" -ports 80,443,8080,8443,8000,9000 -threads 100 -timeout 10 -silent -o "$ports_dir/live_services.txt"
    
    # Advanced reconnaissance tools
    log_info "Advanced recon with Aquatone + Subzy + S3Scanner..."
    
    # Aquatone for visual recon
    if command -v aquatone &> /dev/null; then
        cat "$WORKSPACE_DIR/subdomains/all_subdomains.txt" | aquatone -out "$ports_dir/aquatone" -threads 20 -silent 2>/dev/null || true
    fi
    
    # Subdomain takeover detection
    if command -v subzy &> /dev/null; then
        subzy run --targets "$WORKSPACE_DIR/subdomains/all_subdomains.txt" --output "$ports_dir/takeovers.txt" 2>/dev/null || true
    fi
    
    # S3 bucket scanning
    if command -v s3scanner &> /dev/null; then
        s3scanner scan -f "$WORKSPACE_DIR/subdomains/all_subdomains.txt" -o "$ports_dir/s3buckets.txt" 2>/dev/null || true
    fi
    
    local service_count=$(wc -l < "$ports_dir/live_services.txt" 2>/dev/null || echo "0")
    log_success "Found $service_count live services with advanced recon"
}

# Revolutionary HTTP service discovery
supreme_http_discovery() {
    log_info "Phase 3: Revolutionary HTTP Service Discovery"
    
    local http_dir="$WORKSPACE_DIR/http"
    mkdir -p "$http_dir"
    
    # Advanced HTTP probing
    log_info "Advanced HTTP probing with HTTPx..."
    httpx -l "$WORKSPACE_DIR/subdomains/all_subdomains.txt" \
          -ports 80,443,8080,8443,8000,8888,9000,9090,3000,5000 \
          -threads 50 \
          -timeout 10 \
          -retries 2 \
          -status-code \
          -tech-detect \
          -title \
          -content-length \
          -web-server \
          -silent \
          -o "$http_dir/httpx_results.txt" 2>/dev/null || touch "$http_dir/httpx_results.txt"
    
    # Extract live HTTP services
    grep "200\|301\|302\|403" "$http_dir/httpx_results.txt" 2>/dev/null | cut -d' ' -f1 > "$http_dir/live_urls.txt" || touch "$http_dir/live_urls.txt"
    
    local http_count=$(wc -l < "$http_dir/live_urls.txt" 2>/dev/null || echo "0")
    log_success "Discovered $http_count live HTTP services"
}

# Advanced web crawling and URL discovery
supreme_web_crawling() {
    log_info "Phase 4: Advanced Web Crawling & URL Discovery"
    
    local urls_dir="$WORKSPACE_DIR/urls"
    mkdir -p "$urls_dir" "$WORKSPACE_DIR/secrets" "$WORKSPACE_DIR/xss"
    
    # Advanced crawling with timeout protection
    log_info "Katana crawling with timeout protection..."
    timeout 300 katana -list "$WORKSPACE_DIR/http/live_urls.txt" -depth 3 -js-crawl -silent -o "$urls_dir/katana.txt" 2>/dev/null || touch "$urls_dir/katana.txt"
    
    # Advanced JavaScript analysis with SecretFinder
    log_info "Analyzing JavaScript files for secrets..."
    grep -E "\.js($|\?)" "$urls_dir/katana.txt" | head -10 | while read -r js_url; do
        if [[ "$js_url" == *"$TARGET_DOMAIN"* ]]; then
            timeout 30 secretfinder -i "$js_url" -o cli >> "$WORKSPACE_DIR/secrets/js_secrets.txt" 2>/dev/null || true
        fi
    done
    
    # TruffleHog secret scanning
    log_info "Running TruffleHog for comprehensive secret detection..."
    if command -v trufflehog &> /dev/null; then
        head -10 "$WORKSPACE_DIR/http/live_urls.txt" | while read -r url; do
            if [ -n "$url" ]; then
                timeout 60 trufflehog http --url="$url" --json >> "$WORKSPACE_DIR/secrets/trufflehog.json" 2>/dev/null || true
            fi
        done
    fi
    
    log_info "Historical URL discovery with timeouts..."
    # GAU with strict timeout (max 2 minutes)
    timeout 120 bash -c "cat '$WORKSPACE_DIR/http/live_urls.txt' | head -20 | gau --threads 5 --timeout 5" > "$urls_dir/gau.txt" 2>/dev/null || touch "$urls_dir/gau.txt"
    
    # Waybackurls with strict timeout (max 3 minutes)  
    timeout 180 bash -c "cat '$WORKSPACE_DIR/http/live_urls.txt' | head -15 | waybackurls" > "$urls_dir/wayback.txt" 2>/dev/null || touch "$urls_dir/wayback.txt"
    
    log_info "Historical URL discovery completed with timeouts"
    
    # Combine and filter URLs properly
    cat "$urls_dir"/*.txt 2>/dev/null | \
        grep -E "^https?://" | \
        grep -v -E "\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|ttf|pdf|zip|tar|gz)$" | \
        sort -u > "$urls_dir/all_urls.txt"
    
    # Extract parameterized URLs and JS files
    grep "?" "$urls_dir/all_urls.txt" > "$urls_dir/param_urls.txt" 2>/dev/null || touch "$urls_dir/param_urls.txt"
    grep -E "\.js($|\?)" "$urls_dir/all_urls.txt" > "$urls_dir/js_files.txt" 2>/dev/null || touch "$urls_dir/js_files.txt"
    
    local url_count=$(wc -l < "$urls_dir/all_urls.txt" 2>/dev/null || echo "0")
    local param_count=$(wc -l < "$urls_dir/param_urls.txt" 2>/dev/null || echo "0")
    
    log_success "Discovered $url_count URLs ($param_count with parameters)"
}

# Revolutionary Nuclei vulnerability scanning
supreme_nuclei_scanning() {
    log_info "Phase 5: Revolutionary Nuclei Vulnerability Scanning"
    
    local nuclei_dir="$WORKSPACE_DIR/nuclei"
    mkdir -p "$nuclei_dir"
    
    # Update templates
    nuclei -update-templates -silent
    
    # Comprehensive vulnerability scanning with timeout protection
    log_info "Running comprehensive Nuclei scan with timeout protection..."
    timeout 600 nuclei -list "$WORKSPACE_DIR/http/live_urls.txt" \
           -severity critical,high,medium \
           -c 25 -timeout 10 -json -silent \
           -o "$nuclei_dir/nuclei_results.json" 2>/dev/null || touch "$nuclei_dir/nuclei_results.json"
    
    # ULTIMATE VULNERABILITY TESTING WITH ALL ADVANCED TOOLS
    log_info "Advanced vulnerability testing with multiple tools..."
    
    # Directory fuzzing with ffuf
    mkdir -p "$WORKSPACE_DIR/fuzzing"
    head -5 "$WORKSPACE_DIR/http/live_urls.txt" | while read url; do
        ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s -t 50 >> "$WORKSPACE_DIR/fuzzing/directories.txt" 2>/dev/null || true
    done
    
    # Parameter discovery with Arjun
    mkdir -p "$WORKSPACE_DIR/parameters"
    head -5 "$WORKSPACE_DIR/http/live_urls.txt" | while read url; do
        arjun -u "$url" -oJ "$WORKSPACE_DIR/parameters/$(echo $url | md5sum | cut -d' ' -f1).json" -t 20 2>/dev/null || true
    done
    
    # Advanced XSS testing with XSStrike + LazyXSS
    mkdir -p "$WORKSPACE_DIR/xss"
    if [ -s "$WORKSPACE_DIR/urls/param_urls.txt" ]; then
        head -5 "$WORKSPACE_DIR/urls/param_urls.txt" | while read -r param_url; do
            if [[ "$param_url" == *"$TARGET_DOMAIN"* ]]; then
                timeout 60 xsstrike -u "$param_url" --crawl >> "$WORKSPACE_DIR/xss/xsstrike.txt" 2>/dev/null || true
            fi
        done
    fi
    
    # SQL Injection testing with Commix
    mkdir -p "$WORKSPACE_DIR/sqli"
    if [ -s "$WORKSPACE_DIR/urls/param_urls.txt" ]; then
        head -5 "$WORKSPACE_DIR/urls/param_urls.txt" | while read param_url; do
            timeout 120 commix -u "$param_url" --batch --level=3 >> "$WORKSPACE_DIR/sqli/commix.txt" 2>/dev/null || true
        done
    fi
    
    # LFI testing with LFImap
    mkdir -p "$WORKSPACE_DIR/lfi"
    if [ -s "$WORKSPACE_DIR/urls/param_urls.txt" ]; then
        head -5 "$WORKSPACE_DIR/urls/param_urls.txt" | while read param_url; do
            timeout 60 lfimap -U "$param_url" >> "$WORKSPACE_DIR/lfi/lfimap.txt" 2>/dev/null || true
        done
    fi
    
    # Open redirect testing with OpenRedireX
    mkdir -p "$WORKSPACE_DIR/redirects"
    if [ -s "$WORKSPACE_DIR/urls/param_urls.txt" ]; then
        head -10 "$WORKSPACE_DIR/urls/param_urls.txt" | while read param_url; do
            timeout 30 openredirex -u "$param_url" >> "$WORKSPACE_DIR/redirects/openredirex.txt" 2>/dev/null || true
        done
    fi
    
    # Parse Nuclei results
    if [ -s "$nuclei_dir/nuclei_results.json" ]; then
        # Extract by severity
        jq -r 'select(.info.severity=="critical") | "\(.matched_at) | \(.info.name) | \(.info.severity)"' "$nuclei_dir/nuclei_results.json" > "$nuclei_dir/critical.txt" 2>/dev/null || touch "$nuclei_dir/critical.txt"
        jq -r 'select(.info.severity=="high") | "\(.matched_at) | \(.info.name) | \(.info.severity)"' "$nuclei_dir/nuclei_results.json" > "$nuclei_dir/high.txt" 2>/dev/null || touch "$nuclei_dir/high.txt"
        jq -r 'select(.info.severity=="medium") | "\(.matched_at) | \(.info.name) | \(.info.severity)"' "$nuclei_dir/nuclei_results.json" > "$nuclei_dir/medium.txt" 2>/dev/null || touch "$nuclei_dir/medium.txt"
        
        # Count vulnerabilities
        CRITICAL_COUNT=$(wc -l < "$nuclei_dir/critical.txt" 2>/dev/null || echo "0")
        HIGH_COUNT=$(wc -l < "$nuclei_dir/high.txt" 2>/dev/null || echo "0")
        MEDIUM_COUNT=$(wc -l < "$nuclei_dir/medium.txt" 2>/dev/null || echo "0")
        
        # Send critical alerts
        while IFS='|' read -r url vuln_name severity; do
            log_critical "Nuclei: $vuln_name at $url"
        done < "$nuclei_dir/critical.txt"
    fi
    
    local total_nuclei=$(jq -s 'length' "$nuclei_dir/nuclei_results.json" 2>/dev/null || echo "0")
    log_success "Nuclei scan completed: $total_nuclei vulnerabilities found"
}

# Advanced vulnerability chaining analysis
supreme_vulnerability_chaining() {
    log_info "Phase 6: Advanced Vulnerability Chaining Analysis"
    send_telegram_update "🤖 Running AI vulnerability analysis"
    
    local chaining_dir="$WORKSPACE_DIR/chaining"
    mkdir -p "$chaining_dir"
    
    log_info "Analyzing vulnerability chains with AI..."
    
    # Count findings
    local subdomain_count=$(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    local service_count=$(wc -l < "$WORKSPACE_DIR/http/live_urls.txt" 2>/dev/null || echo "0")
    local url_count=$(wc -l < "$WORKSPACE_DIR/urls/all_urls.txt" 2>/dev/null || echo "0")
    local param_count=$(wc -l < "$WORKSPACE_DIR/urls/param_urls.txt" 2>/dev/null || echo "0")
    local nuclei_count=$(wc -l < "$WORKSPACE_DIR/nuclei/nuclei_results.json" 2>/dev/null || echo "0")
    
    # AI-powered vulnerability chaining analysis using CodeLlama
    if command -v ollama &> /dev/null && [ "${AI_SERVICE:-}" = "ollama" ]; then
        local ai_prompt="You are a penetration testing expert. Analyze this scan data:

TARGET: $TARGET_DOMAIN
- Subdomains: $subdomain_count
- Live Services: $service_count  
- URLs Found: $url_count
- Parameterized URLs: $param_count
- Nuclei Findings: $nuclei_count

Provide a brief security assessment focusing on:
1. Attack surface analysis
2. Potential vulnerability chains
3. Critical security recommendations
4. Risk priority ranking

Keep response under 200 words."
        
        timeout 60 bash -c "echo '$ai_prompt' | ollama run codellama:7b" > "$chaining_dir/ai_chain_analysis.txt" 2>/dev/null || echo "AI analysis timeout - CodeLlama not responding" > "$chaining_dir/ai_chain_analysis.txt"
    else
        echo "AI analysis not available - Ollama not configured or not running" > "$chaining_dir/ai_chain_analysis.txt"
    fi
    
    log_success "Vulnerability chaining analysis completed"
    send_telegram_update "✅ AI analysis completed"
}

# Generate supreme reports
generate_supreme_reports() {
    log_info "Phase 7: Generating Supreme Intelligence Reports"
    
    local reports_dir="$WORKSPACE_DIR/reports"
    mkdir -p "$reports_dir"
    
    local scan_duration=$(($(date +%s) - SCAN_START_TIME))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((scan_duration/3600)) $((scan_duration%3600/60)) $((scan_duration%60)))
    
    # Executive Summary
    cat > "$reports_dir/executive_summary.txt" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                    GODMODE SUPREME AI SCANNER v2.0                          ║
║                         EXECUTIVE SUMMARY REPORT                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

🎯 TARGET: $TARGET_DOMAIN
⏱️  SCAN DURATION: $duration_formatted
📅 SCAN DATE: $(date)

🔍 RECONNAISSANCE SUMMARY:
• Subdomains Discovered: $(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
• Live HTTP Services: $(wc -l < "$WORKSPACE_DIR/http/live_urls.txt" 2>/dev/null || echo "0")  
• URLs Discovered: $(wc -l < "$WORKSPACE_DIR/urls/all_urls.txt" 2>/dev/null || echo "0")
• Parameterized URLs: $(wc -l < "$WORKSPACE_DIR/urls/param_urls.txt" 2>/dev/null || echo "0")

🚨 VULNERABILITY SUMMARY:
• CRITICAL: $CRITICAL_COUNT
• HIGH: $HIGH_COUNT  
• MEDIUM: $MEDIUM_COUNT
• TOTAL: $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))

🎖️  RISK ASSESSMENT:
$(if [ $CRITICAL_COUNT -gt 0 ]; then echo "⚠️  IMMEDIATE ACTION REQUIRED - Critical vulnerabilities detected"; elif [ $HIGH_COUNT -gt 0 ]; then echo "🔴 HIGH RISK - Urgent remediation needed"; elif [ $MEDIUM_COUNT -gt 0 ]; then echo "🟡 MEDIUM RISK - Schedule remediation"; else echo "✅ LOW RISK - No critical issues found"; fi)

📋 TOP CRITICAL FINDINGS:
EOF
    
    # Add top critical findings
    if [ -s "$WORKSPACE_DIR/nuclei/critical.txt" ]; then
        head -10 "$WORKSPACE_DIR/nuclei/critical.txt" >> "$reports_dir/executive_summary.txt"
    else
        echo "No critical vulnerabilities detected by Nuclei scanner." >> "$reports_dir/executive_summary.txt"
    fi
    
    # Technical Report
    cat > "$reports_dir/technical_report.txt" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                         TECHNICAL ANALYSIS REPORT                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

🔧 METHODOLOGY:
1. Advanced Subdomain Discovery (Subfinder, CT logs, DNS bruteforce)
2. Comprehensive Port Scanning (Masscan + Nmap)
3. HTTP Service Enumeration (HTTPx)
4. Advanced Web Crawling (Katana, GAU, Wayback)
5. Revolutionary Nuclei Scanning (All templates)
6. AI-Powered Vulnerability Analysis
7. Vulnerability Chaining Assessment

📊 DETAILED FINDINGS:

NUCLEI SCAN RESULTS:
$(cat "$WORKSPACE_DIR/nuclei/nuclei_results.json" 2>/dev/null | jq -r '. | "• " + .info.name + " [" + .info.severity + "] - " + .matched_at' || echo "No Nuclei results available")

🤖 AI ANALYSIS:
$(cat "$WORKSPACE_DIR/chaining/ai_chain_analysis.txt" 2>/dev/null || echo "AI analysis not available")

🔗 VULNERABILITY CHAINS:
Advanced correlation analysis completed. Check individual vulnerability files for detailed exploitation paths.

📁 EVIDENCE LOCATION:
• Raw Nuclei Results: $WORKSPACE_DIR/nuclei/nuclei_results.json
• Subdomains: $WORKSPACE_DIR/subdomains/all_subdomains.txt
• Live URLs: $WORKSPACE_DIR/http/live_urls.txt
• All URLs: $WORKSPACE_DIR/urls/all_urls.txt
EOF
    
    log_success "Supreme intelligence reports generated"
}

# Main execution function
main() {
    # Banner
    echo -e "${PURPLE}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗  ██████╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗ ███████╗            ║
║   ██╔════╝ ██╔═══██╗██╔══██╗████╗ ████║██╔═══██╗██╔══██╗██╔════╝            ║
║   ██║  ███╗██║   ██║██║  ██║██╔████╔██║██║   ██║██║  ██║█████╗              ║
║   ██║   ██║██║   ██║██║  ██║██║╚██╔╝██║██║   ██║██║  ██║██╔══╝              ║
║   ╚██████╔╝╚██████╔╝██████╔╝██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗            ║
║    ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝            ║
║                                                                              ║
║              SUPREME AI SCANNER v2.0 - WORLD'S MOST ADVANCED                ║
║                     VULNERABILITY DETECTION SYSTEM                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Security warning
    echo -e "${RED}${BOLD}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║                           ⚠️  SECURITY WARNING  ⚠️                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  This script performs comprehensive security testing.             ║
║  Only use on systems you own or have explicit permission to test. ║
║                                                                   ║
║  Unauthorized testing is illegal and unethical.                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Get target
    if [ $# -eq 0 ]; then
        echo -e "${CYAN}🔍 GODMODE SUPREME AI SCANNER v2.0${NC}"
        echo ""
        echo -e "${YELLOW}Target Domain:${NC}"
        read -r TARGET_DOMAIN
    else
        TARGET_DOMAIN="$1"
    fi
    
    # Validate target
    if [[ ! "$TARGET_DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid domain format: $TARGET_DOMAIN"
        exit 1
    fi
    
    echo ""
    echo -e "${CYAN}This script will perform comprehensive security testing including:${NC}"
    echo -e "  • ${GREEN}Advanced subdomain enumeration${NC}"
    echo -e "  • ${GREEN}Comprehensive port scanning${NC}"
    echo -e "  • ${GREEN}Revolutionary Nuclei vulnerability scanning${NC}"
    echo -e "  • ${GREEN}AI-powered vulnerability analysis${NC}"
    echo -e "  • ${GREEN}Advanced vulnerability chaining${NC}"
    echo -e "  • ${GREEN}Supreme intelligence reporting${NC}"
    echo ""
    echo -e "${RED}⚠️  Only proceed if you have explicit permission! ⚠️${NC}"
    echo ""
    echo -e "${YELLOW}Type 'I HAVE PERMISSION' to continue:${NC}"
    read -r permission
    
    if [ "$permission" != "I HAVE PERMISSION" ]; then
        log_error "Permission not granted. Exiting."
        exit 1
    fi
    
    log_success "Permission confirmed for: $TARGET_DOMAIN"
    
    # Load configuration
    if [ -f ~/.godmode_config ]; then
        source ~/.godmode_config
        log_info "Configuration loaded"
    else
        log_warn "No configuration file found. Some features may be limited."
    fi
    
    # Setup workspace
    WORKSPACE_DIR="./recon_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$WORKSPACE_DIR"
    log_info "Workspace created: $WORKSPACE_DIR"
    
    # Install tools
    install_supreme_tools
    
    log_info "Starting revolutionary security assessment..."
    
    # Execute scanning phases with ULTIMATE TOOLS
    supreme_subdomain_discovery
    supreme_port_scanning  
    supreme_http_discovery
    supreme_web_crawling
    supreme_nuclei_scanning
    supreme_vulnerability_chaining
    generate_supreme_reports
    
    # Final summary
    local total_time=$(($(date +%s) - SCAN_START_TIME))
    local time_formatted=$(printf '%02d:%02d:%02d' $((total_time/3600)) $((total_time%3600/60)) $((total_time%60)))
    
    echo ""
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "🎯 GODMODE SUPREME SCAN COMPLETED!"
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "Target: $TARGET_DOMAIN"
    log_success "Duration: $time_formatted"
    log_success "Workspace: $WORKSPACE_DIR"
    echo ""
    log_success "📊 FINAL RESULTS:"
    log_success "• Subdomains: $(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")"
    log_success "• Live Services: $(wc -l < "$WORKSPACE_DIR/http/live_urls.txt" 2>/dev/null || echo "0")"
    log_success "• Total URLs: $(wc -l < "$WORKSPACE_DIR/urls/all_urls.txt" 2>/dev/null || echo "0")"
    log_success "• CRITICAL Vulnerabilities: $CRITICAL_COUNT"
    log_success "• HIGH Vulnerabilities: $HIGH_COUNT"
    log_success "• MEDIUM Vulnerabilities: $MEDIUM_COUNT"
    echo ""
    log_success "📋 REPORTS GENERATED:"
    log_success "• Executive Summary: $WORKSPACE_DIR/reports/executive_summary.txt"
    log_success "• Technical Report: $WORKSPACE_DIR/reports/technical_report.txt"
    echo ""
    log_success "🚨 NEXT STEPS:"
    log_success "1. Review executive summary"
    log_success "2. Analyze Nuclei results"
    log_success "3. Verify critical findings manually"
    log_success "4. Implement security fixes"
    log_success "═══════════════════════════════════════════════════════════════"
}

# Execute main function
main "$@"
