#!/bin/bash

# ========================================================================
# FREE AI SETUP FOR GODMODE BUG HUNTER
# No paid services required - 100% free alternatives
# ========================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PURPLE}🆓 FREE AI SETUP FOR GODMODE BUG HUNTER${NC}"
echo -e "${CYAN}Setting up completely free AI alternatives...${NC}"
echo ""

# Function to setup Ollama (Local AI - 100% Free)
setup_ollama() {
    echo -e "${BLUE}[1/3] Setting up Ollama (Local AI - 100% Free)${NC}"
    
    if ! command -v ollama &> /dev/null; then
        echo -e "${YELLOW}Installing Ollama...${NC}"
        curl -fsSL https://ollama.ai/install.sh | sh
        
        echo -e "${YELLOW}Starting Ollama service...${NC}"
        ollama serve &
        sleep 5
        
        echo -e "${YELLOW}Downloading CodeLlama model (optimized for security analysis)...${NC}"
        ollama pull codellama:7b
        
        echo -e "${GREEN}✅ Ollama setup complete!${NC}"
    else
        echo -e "${GREEN}✅ Ollama already installed${NC}"
    fi
}

# Function to setup Groq API (Free tier)
setup_groq_info() {
    echo -e "${BLUE}[2/3] Groq API Setup Instructions (Free 100k tokens/day)${NC}"
    echo -e "${YELLOW}1. Go to: https://console.groq.com/${NC}"
    echo -e "${YELLOW}2. Sign up for FREE account${NC}"
    echo -e "${YELLOW}3. Create API key${NC}"
    echo -e "${YELLOW}4. Export: export GROQ_API_KEY='your-key-here'${NC}"
    echo ""
}

# Function to setup Google Gemini (Free tier)
setup_gemini_info() {
    echo -e "${BLUE}[3/3] Google Gemini Setup Instructions (Free tier)${NC}"
    echo -e "${YELLOW}1. Go to: https://makersuite.google.com/${NC}"
    echo -e "${YELLOW}2. Sign up for FREE account${NC}"
    echo -e "${YELLOW}3. Create API key${NC}"
    echo -e "${YELLOW}4. Export: export GEMINI_API_KEY='your-key-here'${NC}"
    echo ""
}

# Create free AI configuration
create_free_config() {
    cat > ~/.godmode_config << 'EOF'
# GODMODE Bug Hunter - Free Configuration
# Choose your preferred FREE AI service

# Option 1: Ollama (Local, 100% Free, No internet required)
export AI_SERVICE="ollama"
export OLLAMA_MODEL="codellama:7b"

# Option 2: Groq (Free 100k tokens/day)
# export AI_SERVICE="groq"
# export GROQ_API_KEY="your-groq-api-key"

# Option 3: Google Gemini (Free tier)
# export AI_SERVICE="gemini"
# export GEMINI_API_KEY="your-gemini-api-key"

# Telegram (100% Free)
export TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
export TELEGRAM_CHAT_ID="your-telegram-chat-id"

# Performance settings
export MAX_THREADS=30
export SCAN_DEPTH=3
EOF

    echo -e "${GREEN}✅ Configuration file created at ~/.godmode_config${NC}"
}

# Telegram setup instructions
telegram_setup_info() {
    echo -e "${CYAN}📱 TELEGRAM SETUP (100% FREE)${NC}"
    echo -e "${YELLOW}Step 1: Create Bot${NC}"
    echo -e "  1. Open Telegram app"
    echo -e "  2. Search for @BotFather"
    echo -e "  3. Send /newbot"
    echo -e "  4. Choose name: YourName Security Bot"
    echo -e "  5. Choose username: yourname_security_bot"
    echo -e "  6. Copy the token (123456789:ABCdefGHI...)"
    echo ""
    echo -e "${YELLOW}Step 2: Get Chat ID${NC}"
    echo -e "  1. Search for @userinfobot"
    echo -e "  2. Send /start"
    echo -e "  3. Copy your Chat ID (123456789)"
    echo ""
    echo -e "${YELLOW}Step 3: Configure${NC}"
    echo -e "  Edit ~/.godmode_config and add your tokens"
    echo ""
}

# Main execution
main() {
    setup_ollama
    setup_groq_info
    setup_gemini_info
    create_free_config
    telegram_setup_info
    
    echo -e "${GREEN}🎉 FREE SETUP COMPLETE!${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "${YELLOW}1. Edit ~/.godmode_config with your preferred AI service${NC}"
    echo -e "${YELLOW}2. Add your Telegram bot token and chat ID${NC}"
    echo -e "${YELLOW}3. Run: source ~/.godmode_config${NC}"
    echo -e "${YELLOW}4. Test: ./hunting_working.sh example.com${NC}"
    echo ""
    echo -e "${GREEN}You now have a COMPLETELY FREE god-level bug hunter! 🚀${NC}"
}

main "$@"
