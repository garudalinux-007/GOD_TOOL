#!/bin/bash

# ========================================================================
# SUPREME VULNERABILITY SCANNER v3.0 - ULTIMATE FIXED VERSION
# Author: Stored XSS  
# Fixed Python environment issues + streamlined for immediate use
# ========================================================================

set -euo pipefail

# Colors
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
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Set correct PATH for tools
export PATH="/home/user/go/bin:$HOME/go/bin:$PATH"

# Logging functions
log_info() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1"; }
log_critical() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}${BOLD}[CRITICAL]${NC} $1"; ((CRITICAL_COUNT++)); send_critical_alert "$1"; }

# Critical alerts
send_critical_alert() {
    local message="$1"
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=🚨 CRITICAL: $TARGET_DOMAIN%0A$message%0ATime: $(date '+%H:%M:%S')" >/dev/null 2>&1 || true
    fi
}

# FIXED: Python environment setup
setup_python_tools() {
    log_info "Setting up Python-based security tools..."
    
    # Create virtual environment for security tools
    if [ ! -d ~/security_venv ]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv ~/security_venv
    fi
    
    # Activate virtual environment
    source ~/security_venv/bin/activate
    
    # Upgrade pip in virtual environment
    pip install --upgrade pip >/dev/null 2>&1
    
    # Install Python security tools in virtual environment
    if [ ! -d ~/security-tools ]; then
        mkdir -p ~/security-tools
        cd ~/security-tools
        
        # XSStrike
        if [ ! -d "XSStrike" ]; then
            log_info "Installing XSStrike in virtual environment..."
            git clone https://github.com/s0md3v/XSStrike.git >/dev/null 2>&1
            cd XSStrike
            pip install -r requirements.txt >/dev/null 2>&1
            cd ..
        fi
        
        # Install essential Python tools
        log_info "Installing Python security libraries..."
        pip install requests beautifulsoup4 lxml tld fuzzywuzzy >/dev/null 2>&1
        
        cd - > /dev/null
    fi
    
    log_success "Python security tools ready in virtual environment"
}

# AI Analysis Function
ai_analyze_vulnerability() {
    local url="$1" vuln_type="$2" payload="$3" response="$4"
    
    if [ -z "${AI_SERVICE:-}" ]; then
        echo "AI analysis: Manual review recommended for $vuln_type at $url"
        return
    fi
    
    local prompt="Security Analysis: URL=$url, Vuln=$vuln_type. Assess: Real threat? Risk level? Exploitable?"
    
    case "$AI_SERVICE" in
        "gemini")
            if [ -n "${GEMINI_API_KEY:-}" ]; then
                curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY}" \
                    -H 'Content-Type: application/json' \
                    -d "{\"contents\":[{\"parts\":[{\"text\":\"$prompt\"}]}]}" | \
                    jq -r '.candidates[0].content.parts[0].text' 2>/dev/null || echo "AI: $vuln_type needs manual verification"
            else
                echo "AI: Configure GEMINI_API_KEY for analysis"
            fi
            ;;
        "ollama")
            curl -s -X POST http://localhost:11434/api/generate \
                -H "Content-Type: application/json" \
                -d "{\"model\": \"${OLLAMA_MODEL:-codellama:7b}\",\"prompt\": \"$prompt\",\"stream\": false}" | \
                jq -r '.response' 2>/dev/null || echo "AI: Ollama analysis unavailable"
            ;;
        *)
            echo "AI: Configure AI_SERVICE (gemini/ollama) for automated analysis"
            ;;
    esac
}

# Phase 1: Advanced Reconnaissance
supreme_recon() {
    log_info "Phase 1: Advanced Reconnaissance & Subdomain Discovery"
    mkdir -p "$WORKSPACE_DIR/recon"
    
    # Subfinder
    log_info "Running Subfinder..."
    subfinder -d "$TARGET_DOMAIN" -all -silent -o "$WORKSPACE_DIR/recon/subfinder.txt" 2>/dev/null || log_warn "Subfinder issues"
    
    # Amass
    log_info "Running Amass..."
    timeout 120 amass enum -d "$TARGET_DOMAIN" -o "$WORKSPACE_DIR/recon/amass.txt" 2>/dev/null || log_warn "Amass timeout/issues"
    
    # Assetfinder
    log_info "Running Assetfinder..."
    assetfinder --subs-only "$TARGET_DOMAIN" > "$WORKSPACE_DIR/recon/assetfinder.txt" 2>/dev/null || log_warn "Assetfinder issues"
    
    # Combine results
    cat "$WORKSPACE_DIR/recon/"*.txt 2>/dev/null | sort -u | anew "$WORKSPACE_DIR/recon/all_subdomains.txt" >/dev/null
    
    local sub_count=$(wc -l < "$WORKSPACE_DIR/recon/all_subdomains.txt" 2>/dev/null || echo "0")
    log_success "Reconnaissance: Found $sub_count subdomains"
}

# Phase 2: HTTP Service Discovery
supreme_http_discovery() {
    log_info "Phase 2: HTTP Service Discovery & Technology Detection"
    mkdir -p "$WORKSPACE_DIR/http"
    
    log_info "Probing HTTP services with HTTPx..."
    httpx -l "$WORKSPACE_DIR/recon/all_subdomains.txt" \
        -ports 80,443,8080,8443,8000,8888,9000,9090,3000,5000,7000,7001 \
        -threads 50 -timeout 15 -tech-detect -status-code -title \
        -follow-redirects -silent \
        -o "$WORKSPACE_DIR/http/httpx_detailed.txt" 2>/dev/null || log_warn "HTTPx issues"
    
    # Extract clean URLs
    grep -oE 'https?://[^[:space:]]+' "$WORKSPACE_DIR/http/httpx_detailed.txt" 2>/dev/null | \
        cut -d' ' -f1 | sort -u > "$WORKSPACE_DIR/http/live_urls.txt" || touch "$WORKSPACE_DIR/http/live_urls.txt"
    
    local live_count=$(wc -l < "$WORKSPACE_DIR/http/live_urls.txt" 2>/dev/null || echo "0")
    log_success "HTTP Discovery: Found $live_count live services"
}

# Phase 3: Web Crawling & Content Discovery
supreme_web_crawling() {
    log_info "Phase 3: Web Crawling & Content Discovery"
    mkdir -p "$WORKSPACE_DIR/crawling"
    
    # Katana crawling
    log_info "Deep crawling with Katana..."
    katana -list "$WORKSPACE_DIR/http/live_urls.txt" \
        -depth 3 -js-crawl -timeout 15 -concurrency 10 \
        -silent -o "$WORKSPACE_DIR/crawling/katana.txt" 2>/dev/null || log_warn "Katana issues"
    
    # GAU for archived URLs
    log_info "Gathering archived URLs with GAU..."
    timeout 60 gau --threads 5 --timeout 10 < "$WORKSPACE_DIR/http/live_urls.txt" > "$WORKSPACE_DIR/crawling/gau.txt" 2>/dev/null || log_warn "GAU timeout"
    
    # Waybackurls
    log_info "Fetching Wayback URLs..."
    timeout 60 waybackurls < "$WORKSPACE_DIR/http/live_urls.txt" > "$WORKSPACE_DIR/crawling/wayback.txt" 2>/dev/null || log_warn "Waybackurls timeout"
    
    # Combine all URLs
    cat "$WORKSPACE_DIR/crawling/"*.txt 2>/dev/null | sort -u | anew "$WORKSPACE_DIR/crawling/all_urls.txt" >/dev/null
    
    # Extract interesting files
    grep -iE '\.(js|json|xml|txt|log|backup|old|bak)(\?|$)' "$WORKSPACE_DIR/crawling/all_urls.txt" > "$WORKSPACE_DIR/crawling/interesting_files.txt" 2>/dev/null || touch "$WORKSPACE_DIR/crawling/interesting_files.txt"
    
    local url_count=$(wc -l < "$WORKSPACE_DIR/crawling/all_urls.txt" 2>/dev/null || echo "0")
    local file_count=$(wc -l < "$WORKSPACE_DIR/crawling/interesting_files.txt" 2>/dev/null || echo "0")
    log_success "Web Crawling: $url_count URLs, $file_count interesting files"
}

# Phase 4: Vulnerability Scanning
supreme_vuln_scanning() {
    log_info "Phase 4: Comprehensive Vulnerability Scanning"
    mkdir -p "$WORKSPACE_DIR/vulns"
    
    # Nuclei - Main vulnerability scanner
    log_info "Running Nuclei vulnerability scan..."
    nuclei -list "$WORKSPACE_DIR/http/live_urls.txt" \
        -severity critical,high,medium,low \
        -threads 15 -timeout 15 -retries 1 \
        -json -silent -no-interactsh \
        -o "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null || log_warn "Nuclei scan issues"
    
    # Directory fuzzing with ffuf
    log_info "Directory fuzzing with ffuf..."
    if [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    else
        # Create basic wordlist
        echo -e "admin\nlogin\napi\ntest\nbackup\nconfig\nadmin.php\nlogin.php\n.env\n.git\nrobot.txt\nsitemap.xml" > "$WORKSPACE_DIR/vulns/basic_wordlist.txt"
        WORDLIST="$WORKSPACE_DIR/vulns/basic_wordlist.txt"
    fi
    
    head -3 "$WORKSPACE_DIR/http/live_urls.txt" | while read -r url; do
        if [ -n "$url" ]; then
            timeout 30 ffuf -u "$url/FUZZ" -w "$WORDLIST" \
                -mc 200,201,202,301,302,307,401,403 \
                -ac -t 10 -timeout 10 -s \
                -o "$WORKSPACE_DIR/vulns/ffuf_$(echo "$url" | sed 's|https\?://||g' | tr '/' '_' | tr '.' '_').json" \
                -of json 2>/dev/null || echo "ffuf timeout for $url"
        fi
    done
    
    # XSS scanning with dalfox
    log_info "XSS scanning with Dalfox..."
    head -5 "$WORKSPACE_DIR/http/live_urls.txt" > "$WORKSPACE_DIR/vulns/xss_targets.txt"
    timeout 120 dalfox file "$WORKSPACE_DIR/vulns/xss_targets.txt" \
        --output "$WORKSPACE_DIR/vulns/dalfox.txt" \
        --silence 2>/dev/null || log_warn "Dalfox timeout"
    
    # Count vulnerabilities from Nuclei
    if [ -f "$WORKSPACE_DIR/vulns/nuclei.json" ] && [ -s "$WORKSPACE_DIR/vulns/nuclei.json" ]; then
        CRITICAL_COUNT=$(jq -r 'select(.info.severity=="critical") | .info.name' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null | wc -l || echo "0")
        HIGH_COUNT=$(jq -r 'select(.info.severity=="high") | .info.name' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null | wc -l || echo "0")
        MEDIUM_COUNT=$(jq -r 'select(.info.severity=="medium") | .info.name' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null | wc -l || echo "0")
    fi
    
    log_success "Vulnerability Scan: Critical=$CRITICAL_COUNT, High=$HIGH_COUNT, Medium=$MEDIUM_COUNT"
}

# Phase 5: AI Analysis
supreme_ai_analysis() {
    log_info "Phase 5: AI-Powered Security Analysis"
    mkdir -p "$WORKSPACE_DIR/ai_analysis"
    
    echo "Supreme AI Security Analysis Report - $(date)" > "$WORKSPACE_DIR/ai_analysis/ai_report.txt"
    echo "=============================================" >> "$WORKSPACE_DIR/ai_analysis/ai_report.txt"
    echo "" >> "$WORKSPACE_DIR/ai_analysis/ai_report.txt"
    
    if [ -f "$WORKSPACE_DIR/vulns/nuclei.json" ] && [ -s "$WORKSPACE_DIR/vulns/nuclei.json" ]; then
        log_info "Analyzing critical/high severity findings with AI..."
        
        # Process critical and high severity vulnerabilities
        jq -r 'select(.info.severity=="critical" or .info.severity=="high") | @json' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null | head -5 | while IFS= read -r line; do
            if [ -n "$line" ]; then
                url=$(echo "$line" | jq -r '.matched_at' 2>/dev/null || echo "Unknown")
                vuln=$(echo "$line" | jq -r '.info.name' 2>/dev/null || echo "Unknown")
                severity=$(echo "$line" | jq -r '.info.severity' 2>/dev/null || echo "Unknown")
                description=$(echo "$line" | jq -r '.info.description' 2>/dev/null || echo "No description")
                
                {
                    echo "VULNERABILITY: $vuln"
                    echo "URL: $url"
                    echo "SEVERITY: $(echo "$severity" | tr '[:lower:]' '[:upper:]')"
                    echo "DESCRIPTION: $description"
                    echo ""
                    
                    ai_result=$(ai_analyze_vulnerability "$url" "$vuln" "N/A" "$description")
                    echo "AI ANALYSIS: $ai_result"
                    echo "RECOMMENDATION: Immediate manual verification required"
                    echo "================================================"
                    echo ""
                } >> "$WORKSPACE_DIR/ai_analysis/ai_report.txt"
            fi
        done
    else
        echo "No high/critical vulnerabilities found for AI analysis" >> "$WORKSPACE_DIR/ai_analysis/ai_report.txt"
    fi
    
    log_success "AI analysis completed"
}

# Phase 6: Report Generation
supreme_reporting() {
    log_info "Phase 6: Generating Supreme Security Report"
    mkdir -p "$WORKSPACE_DIR/reports"
    
    # Executive Summary
    cat > "$WORKSPACE_DIR/reports/executive_summary.txt" << EOF
SUPREME VULNERABILITY SCANNER EXECUTIVE REPORT
===============================================
Target: $TARGET_DOMAIN
Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
Duration: $(($(date +%s) - SCAN_START_TIME)) seconds
Scanner: Supreme v3.0 Ultimate

SECURITY SUMMARY:
🔴 Critical Vulnerabilities: $CRITICAL_COUNT
🟠 High Risk Vulnerabilities: $HIGH_COUNT  
🟡 Medium Risk Issues: $MEDIUM_COUNT
📊 Total Security Issues: $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))

RECONNAISSANCE RESULTS:
🔍 Subdomains Discovered: $(wc -l < "$WORKSPACE_DIR/recon/all_subdomains.txt" 2>/dev/null || echo "0")
🌐 Live HTTP Services: $(wc -l < "$WORKSPACE_DIR/http/live_urls.txt" 2>/dev/null || echo "0")
🕷️  URLs Crawled: $(wc -l < "$WORKSPACE_DIR/crawling/all_urls.txt" 2>/dev/null || echo "0")
📄 Interesting Files: $(wc -l < "$WORKSPACE_DIR/crawling/interesting_files.txt" 2>/dev/null || echo "0")

CRITICAL SECURITY FINDINGS:
EOF
    
    # Add critical findings
    if [ -f "$WORKSPACE_DIR/vulns/nuclei.json" ] && [ -s "$WORKSPACE_DIR/vulns/nuclei.json" ]; then
        jq -r 'select(.info.severity=="critical") | "🚨 " + .info.name + " → " + .matched_at' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null >> "$WORKSPACE_DIR/reports/executive_summary.txt" || echo "No critical vulnerabilities detected" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    else
        echo "No critical vulnerabilities detected" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    fi
    
    echo "" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    echo "HIGH PRIORITY FINDINGS:" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    
    if [ -f "$WORKSPACE_DIR/vulns/nuclei.json" ] && [ -s "$WORKSPACE_DIR/vulns/nuclei.json" ]; then
        jq -r 'select(.info.severity=="high") | "⚠️  " + .info.name + " → " + .matched_at' "$WORKSPACE_DIR/vulns/nuclei.json" 2>/dev/null >> "$WORKSPACE_DIR/reports/executive_summary.txt" || echo "No high-risk vulnerabilities detected" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    else
        echo "No high-risk vulnerabilities detected" >> "$WORKSPACE_DIR/reports/executive_summary.txt"
    fi
    
    # Technical Report
    echo "SUPREME SCANNER TECHNICAL ANALYSIS REPORT" > "$WORKSPACE_DIR/reports/technical_report.txt"
    echo "===========================================" >> "$WORKSPACE_DIR/reports/technical_report.txt"
    echo "Generated: $(date)" >> "$WORKSPACE_DIR/reports/technical_report.txt"
    echo "" >> "$WORKSPACE_DIR/reports/technical_report.txt"
    
    # Include all scan results
    for result_file in "$WORKSPACE_DIR"/vulns/*.json "$WORKSPACE_DIR"/vulns/*.txt "$WORKSPACE_DIR"/crawling/*.txt; do
        if [ -f "$result_file" ] && [ -s "$result_file" ]; then
            echo "=== $(basename "$result_file" | tr '[:lower:]' '[:upper:]') ===" >> "$WORKSPACE_DIR/reports/technical_report.txt"
            head -20 "$result_file" >> "$WORKSPACE_DIR/reports/technical_report.txt" 2>/dev/null
            echo "" >> "$WORKSPACE_DIR/reports/technical_report.txt"
        fi
    done
    
    log_success "Comprehensive security reports generated"
}

# Main execution
main() {
    clear
    echo -e "${PURPLE}${BOLD}"
    echo "██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ "
    echo "██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗"
    echo "██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝"
    echo "╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗"
    echo " ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║"
    echo "  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"
    echo ""
    echo "                        SUPREME VULNERABILITY SCANNER v3.0"
    echo "                      Advanced AI-Powered Security Testing Suite"
    echo "================================================================"
    echo -e "${NC}"
    
    # Input validation
    if [ $# -eq 0 ]; then
        echo -e "${CYAN}Enter target domain:${NC}"
        read -r TARGET_DOMAIN
    else
        TARGET_DOMAIN=$1
    fi
    
    # Domain validation
    if [[ ! "$TARGET_DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        log_error "Invalid domain format: $TARGET_DOMAIN"
        exit 1
    fi
    
    # Permission check
    echo -e "${YELLOW}${BOLD}⚖️  ETHICAL HACKING DISCLAIMER ⚖️${NC}"
    echo "This tool should ONLY be used on:"
    echo "  • Systems you own"
    echo "  • Systems with explicit written permission"  
    echo "  • Bug bounty programs with valid scope"
    echo ""
    read -p "Type 'I HAVE PERMISSION' to continue: " permission
    
    if [ "$permission" != "I HAVE PERMISSION" ]; then
        log_error "Permission not granted. Exiting for ethical compliance."
        exit 1
    fi
    
    # Setup workspace
    WORKSPACE_DIR="./supreme_scan_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$WORKSPACE_DIR"
    
    echo ""
    log_info "🎯 Target: $TARGET_DOMAIN"
    log_info "📁 Workspace: $WORKSPACE_DIR"
    log_info "🚀 Starting comprehensive security assessment..."
    echo ""
    
    # Execute all phases
    setup_python_tools
    supreme_recon
    supreme_http_discovery
    supreme_web_crawling
    supreme_vuln_scanning
    supreme_ai_analysis
    supreme_reporting
    
    # Final summary with colors
    echo ""
    echo -e "${GREEN}${BOLD}✅ SUPREME SCAN COMPLETED SUCCESSFULLY! ✅${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    
    # Results summary
    echo -e "${CYAN}📊 SCAN RESULTS SUMMARY:${NC}"
    echo -e "   🔴 Critical Issues: ${RED}$CRITICAL_COUNT${NC}"
    echo -e "   🟠 High Risk Issues: ${YELLOW}$HIGH_COUNT${NC}"
    echo -e "   🟡 Medium Risk Issues: $MEDIUM_COUNT"
    
    echo ""
    echo -e "${BLUE}📁 GENERATED REPORTS:${NC}"
    echo -e "   📋 Executive Summary: ${GREEN}$WORKSPACE_DIR/reports/executive_summary.txt${NC}"
    echo -e "   🔍 Technical Report: ${GREEN}$WORKSPACE_DIR/reports/technical_report.txt${NC}"
    echo -e "   🤖 AI Analysis: ${GREEN}$WORKSPACE_DIR/ai_analysis/ai_report.txt${NC}"
    
    # Critical warnings
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${RED}${BOLD}🚨 CRITICAL ALERT: $CRITICAL_COUNT CRITICAL VULNERABILITIES FOUND! 🚨${NC}"
        echo -e "${RED}Immediate attention required!${NC}"
    fi
    
    # Success metrics
    local scan_duration=$(($(date +%s) - SCAN_START_TIME))
    echo ""
    echo -e "${GREEN}⏱️  Scan Duration: ${scan_duration} seconds${NC}"
    echo -e "${GREEN}🎯 Target Analysis: Complete${NC}"
    
    log_success "Supreme security assessment completed successfully!"
}

# Execute main function with all arguments
main "$@"
