#!/bin/bash
# iptables IP Blocklist Implementation Script
# Description: Apply IP blocklists to iptables firewall
# Usage: ./iptables.sh [blocklist_file]

set -euo pipefail

# Configuration
BLOCKLIST_DIR="../blocklists"
CHAIN_NAME="IP_BLOCKLIST"
LOG_DROPS=true

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Check if iptables is available
if ! command -v iptables &> /dev/null; then
    log_error "iptables not found. Please install iptables."
    exit 1
fi

# Create custom chain if it doesn't exist
create_chain() {
    if ! iptables -L "$CHAIN_NAME" -n &> /dev/null; then
        log_info "Creating custom chain: $CHAIN_NAME"
        iptables -N "$CHAIN_NAME"
        
        # Insert chain into INPUT chain (at the beginning for efficiency)
        iptables -I INPUT -j "$CHAIN_NAME"
        
        log_info "Chain created and linked to INPUT"
    else
        log_info "Chain $CHAIN_NAME already exists"
    fi
}

# Flush existing rules in our chain
flush_chain() {
    log_info "Flushing existing rules from $CHAIN_NAME"
    iptables -F "$CHAIN_NAME"
}

# Add IP to blocklist
block_ip() {
    local ip=$1
    
    # Skip empty lines
    [[ -z "$ip" ]] && return
    
    # Skip comments
    [[ "$ip" =~ ^#.*$ ]] && return
    
    # Validate IP format (basic check)
    if [[ "$ip" =~ ^[0-9.:/]+$ ]] || [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        if [[ "$LOG_DROPS" == true ]]; then
            # Log dropped packets (limit to avoid log flooding)
            iptables -A "$CHAIN_NAME" -s "$ip" -m limit --limit 5/min -j LOG --log-prefix "IP_BLOCKED: "
        fi
        
        # Drop the packet
        iptables -A "$CHAIN_NAME" -s "$ip" -j DROP
        echo -n "."
    else
        log_warn "Invalid IP format: $ip"
    fi
}

# Load blocklist from file
load_blocklist() {
    local file=$1
    
    if [[ ! -f "$file" ]]; then
        log_error "Blocklist file not found: $file"
        return 1
    fi
    
    log_info "Loading blocklist from: $file"
    
    local count=0
    while IFS= read -r line; do
        block_ip "$line"
        ((count++))
    done < "$file"
    
    echo "" # New line after dots
    log_info "Processed $count lines from blocklist"
}

# Show statistics
show_stats() {
    log_info "Current blocklist statistics:"
    echo ""
    iptables -L "$CHAIN_NAME" -n -v --line-numbers | head -20
    
    local total_rules=$(iptables -L "$CHAIN_NAME" -n | grep -c "DROP" || echo "0")
    echo ""
    log_info "Total blocking rules: $total_rules"
}

# Remove chain (cleanup)
remove_chain() {
    log_info "Removing IP blocklist chain"
    
    # Remove reference from INPUT chain
    iptables -D INPUT -j "$CHAIN_NAME" 2>/dev/null || true
    
    # Flush and delete the chain
    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    iptables -X "$CHAIN_NAME" 2>/dev/null || true
    
    log_info "Chain removed"
}

# Main menu
show_menu() {
    echo ""
    echo "======================================="
    echo "  IP Blocklist Management for iptables"
    echo "======================================="
    echo "1. Apply malware blocklist"
    echo "2. Apply botnet blocklist"
    echo "3. Apply Tor exit nodes blocklist"
    echo "4. Apply abuse blocklist"
    echo "5. Apply all blocklists"
    echo "6. Show current statistics"
    echo "7. Remove all blocklist rules"
    echo "8. Exit"
    echo "======================================="
}

# Main execution
main() {
    if [[ $# -eq 1 ]]; then
        # Single blocklist specified
        create_chain
        flush_chain
        load_blocklist "$1"
        show_stats
        exit 0
    fi
    
    # Interactive mode
    while true; do
        show_menu
        read -p "Select option (1-8): " choice
        
        case $choice in
            1)
                create_chain
                flush_chain
                load_blocklist "$BLOCKLIST_DIR/malware.txt"
                show_stats
                ;;
            2)
                create_chain
                flush_chain
                load_blocklist "$BLOCKLIST_DIR/botnet.txt"
                show_stats
                ;;
            3)
                create_chain
                flush_chain
                load_blocklist "$BLOCKLIST_DIR/tor-exit.txt"
                show_stats
                ;;
            4)
                create_chain
                flush_chain
                load_blocklist "$BLOCKLIST_DIR/abuse.txt"
                show_stats
                ;;
            5)
                create_chain
                flush_chain
                for file in "$BLOCKLIST_DIR"/*.txt; do
                    load_blocklist "$file"
                done
                show_stats
                ;;
            6)
                show_stats
                ;;
            7)
                remove_chain
                ;;
            8)
                log_info "Exiting"
                exit 0
                ;;
            *)
                log_error "Invalid option"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"
