#!/bin/bash
# PRISM - Complete Universal Converter & CTF Toolkit

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Check for required tools
check_dependencies() {
    local missing=()
    for tool in xxd python3 awk sed tr md5sum; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: The following required tools are missing:${NC}"
        for m in "${missing[@]}"; do echo "  - $m"; done
        echo -e "${YELLOW}Please install them to use PRISM.${NC}"
        exit 1
    fi
}

# Function to normalize format names
normalize_format() {
    case "$1" in
        hex|hexadecimal|h) echo "hex" ;;
        ascii|text|a) echo "ascii" ;;
        bin|binary|b) echo "bin" ;;
        dec|decimal|d) echo "dec" ;;
        oct|octal|o) echo "oct" ;;
        base32|b32) echo "base32" ;;
        base64|b64) echo "base64" ;;
        url|percent) echo "url" ;;
        unicode|uni|u) echo "unicode" ;;
        rot13|rot) echo "rot13" ;;
        utf8|utf-8) echo "utf8" ;;
        utf16|utf-16) echo "utf16" ;;
        utf32|utf-32) echo "utf32" ;;
        all) echo "all" ;;
        # Hashes
        md5) echo "md5" ;;
        sha1) echo "sha1" ;;
        sha256) echo "sha256" ;;
        sha384) echo "sha384" ;;
        sha512) echo "sha512" ;;
        crc32) echo "crc32" ;;
        *) echo "$1" ;;
    esac
}

# Function to clean input
clean_input() {
    local input="$1"
    local format="$2"
    
    case "$format" in
        hex)
            echo "$input" | tr -d ' \n\r' | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
            ;;
        bin)
            echo "$input" | tr -cd '01' | sed 's/ //g'
            ;;
        dec)
            echo "$input" | tr -cd '0-9 ' | sed 's/  */ /g'
            ;;
        oct)
            echo "$input" | tr -cd '0-7 ' | sed 's/  */ /g'
            ;;
        base32)
            echo "$input" | tr -d ' \n\r=' | tr '[:lower:]' '[:upper:]'
            ;;
        base64)
            echo "$input" | tr -d ' \n\r='
            ;;
        url)
            echo "$input" | sed 's/%/\\x/g'
            ;;
        unicode)
             echo "$input" | sed 's/[Uu]+//g'
             ;;
        utf8|utf16|utf32)
             # These are hex representations
             echo "$input" | tr -d ' \n\r' | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
             ;;
        *)
            echo "$input"
            ;;
    esac
}

# Conversion functions
hex_to_ascii() {
    local hex="$1"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    echo -n "$hex" | xxd -r -p 2>/dev/null || python3 -c "
import sys, binascii
try:
    print(binascii.unhexlify(sys.argv[1]).decode(), end='')
except:
    print('', end='')
" "$hex"
}

ascii_to_hex() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -p | tr -d '\n'
}

bin_to_ascii() {
    local hex=$(bin_to_hex "$1")
    hex_to_ascii "$hex"
}

# NEW: Optimized ascii_to_bin that removes unnecessary leading zeros
ascii_to_bin() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n'
}

dec_to_ascii() {
    local hex=$(dec_to_hex "$1")
    hex_to_ascii "$hex"
}

ascii_to_dec() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -p | sed 's/../& /g' | tr ' ' '\n' | while read hex; do
        [ -n "$hex" ] && printf "%d " "0x$hex"
    done | sed 's/ $//'
}

oct_to_ascii() {
    local hex=$(for num in $1; do printf "%02x" "0$num"; done)
    hex_to_ascii "$hex"
}

# FIXED: Parsing
# FIXED: helper for oct_to_bin
# FIXED: Safe implementations using hex intermediate
ascii_to_oct() {
    local stream
    if [ -n "$1" ]; then stream=$(echo -n "$1"); else stream=$(cat); fi
    for hex in $(echo -n "$stream" | xxd -p | sed 's/../& /g'); do
        printf "%03o " "0x$hex"
    done | sed 's/ $//'
}

oct_to_bin() {
    local hex=$(for num in $1; do printf "%02x" "0$num"; done)
    hex_to_bin "$hex"
}

# NEW: Unicode Helpers
ascii_to_unicode() {
    # If explicit arg, echo it. Else assume stdin.
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
chars = sys.stdin.read()
print(' '.join([f'U+{ord(c):04X}' for c in chars]), end='')
"
}

unicode_to_ascii() {
    # Expects space separated hex string (e.g., 0041 0042)
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    code_points = sys.stdin.read().split()
    print(''.join([chr(int(cp, 16)) for cp in code_points]), end='')
except: pass
"
}

# NEW: Generic Python Encoding Helper (Text <-> Hex)
text_to_encoded_hex() {
    local codec="$1"
    # Read raw bytes from stdin, treat as Latin-1 (1:1 byte mapping) to get string, then encode
    python3 -c "
import sys
try:
    data = sys.stdin.buffer.read()
    # Decode input bytes to string using latin-1 (safest 1:1 mapping)
    text = data.decode('latin-1')
    # Encode to target codec and print hex
    print(text.encode('$codec').hex(), end='')
except Exception as e:
    print(f'Error: {str(e)}')
"
}

encoded_hex_to_text() {
    local codec="$1"
    local hex="$2"
    echo -n "$hex" | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode('$codec', errors='ignore'), end='')"
}

# FIXED: bin_to_hex with dynamic padding
bin_to_hex() {
    local bin="$1"
    # Remove spaces
    bin=$(echo "$bin" | tr -d ' ')
    # Calculate how many bits we need to pad to make complete bytes
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert each byte (8 bits) to hex
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "%02x" $((2#$byte))
    done
}

# FIXED: hex_to_bin - remove leading zeros
hex_to_bin() {
    local hex="$1"
    # Ensure even length
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    # Efficiently convert to binary stream using xxd (strip offsets and ASCII dump)
    echo -n "$hex" | xxd -r -p 2>/dev/null | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n'
}

dec_to_hex() {
    for num in $1; do
        printf "%02x" "$num"
    done
}

hex_to_dec() {
    local hex="$1"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    for ((i=0; i<${#hex}; i+=2)); do
        printf "%d " "0x${hex:i:2}"
    done | sed 's/ $//'
}

# FIXED: dec_to_bin - remove leading zeros
dec_to_bin() {
    local hex=$(dec_to_hex "$1")
    hex_to_bin "$hex"
}

# FIXED: bin_to_dec with dynamic padding
bin_to_dec() {
    local bin="$1"
    # Remove spaces
    bin=$(echo "$bin" | tr -d ' ')
    # Pad to complete bytes if needed
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert each byte to decimal
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "%d " $((2#$byte))
    done | sed 's/ $//'
}




# NEW: Hashing Function
hash_string() {
    local input="$1"
    local algo="$2"
    
    case "$algo" in
        md5)    echo -n "$input" | md5sum | awk '{print $1}' ;;
        sha1)   echo -n "$input" | sha1sum | awk '{print $1}' ;;
        sha256) echo -n "$input" | sha256sum | awk '{print $1}' ;;
        sha384) echo -n "$input" | sha384sum | awk '{print $1}' ;;
        sha512) echo -n "$input" | sha512sum | awk '{print $1}' ;;
        crc32)  echo -n "$input" | crc32 /dev/stdin ;;
    esac
}

# Advanced Hashing (takes hex representation)
hash_hex() {
    local hex="$1"
    local algo="$2"
    if [ "$algo" == "crc32" ]; then
        echo -n "$hex" | xxd -r -p | crc32 /dev/stdin
    else
        echo -n "$hex" | xxd -r -p | ${algo}sum | awk '{print $1}'
    fi
}

# Internal function to perform conversion without UI output
perform_conversion() {
    local input="$1"
    local from="$2"
    local to="$3"
    
    # Pre-clean input
    local cleaned=$(clean_input "$input" "$from")
    
    case "$from.$to" in
        # ASCII Conversions
        ascii.ascii) echo "$input" ;;
        ascii.hex) ascii_to_hex "$input" ;;
        ascii.bin) ascii_to_bin "$input" ;;
        ascii.dec) ascii_to_dec "$input" ;;
        ascii.oct) ascii_to_oct "$input" ;;
        ascii.base32) echo -n "$input" | base32 ;;
        ascii.base64) echo -n "$input" | base64 ;;
        ascii.unicode) ascii_to_unicode "$input" ;;
        ascii.url) echo -n "$input" | xxd -p | sed 's/../%&/g' ;;
        ascii.rot13) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        # UTF Encoders (ASCII -> Hex Rep)
        ascii.utf8) echo -n "$input" | text_to_encoded_hex "utf-8" ;;
        ascii.utf16) echo -n "$input" | text_to_encoded_hex "utf-16" ;;
        ascii.utf32) echo -n "$input" | text_to_encoded_hex "utf-32" ;;

        # UTF Decoders (Hex Rep -> ASCII)
        utf8.ascii) encoded_hex_to_text "utf-8" "$cleaned" ;;
        utf16.ascii) encoded_hex_to_text "utf-16" "$cleaned" ;;
        utf32.ascii) encoded_hex_to_text "utf-32" "$cleaned" ;;
        
        # Hex Conversions
        hex.ascii) hex_to_ascii "$cleaned" ;;
        hex.hex) echo "$cleaned" ;;
        hex.bin) hex_to_bin "$cleaned" ;;
        hex.dec) hex_to_dec "$cleaned" ;;
        hex.oct) 
            vals=$(hex_to_dec "$cleaned")
            for num in $vals; do printf "%03o " "$num"; done | sed 's/ $//' 
            ;;
        hex.base32) hex_to_ascii "$cleaned" | base32 ;;
        hex.base64) hex_to_ascii "$cleaned" | base64 ;;
        hex.unicode) hex_to_ascii "$cleaned" | ascii_to_unicode ;;
        hex.url) hex_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # UTF Encoders (from Hex)
        hex.utf8) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-8" ;;
        hex.utf16) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-16" ;;
        hex.utf32) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-32" ;;
        
        # ROT13 (from Hex)
        hex.rot13) hex_to_ascii "$cleaned" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        # Binary Conversions
        bin.ascii) bin_to_ascii "$cleaned" ;;
        bin.hex) bin_to_hex "$cleaned" ;;
        bin.bin) echo "$cleaned" ;;
        bin.dec) bin_to_dec "$cleaned" ;;
        bin.oct) 
            vals=$(bin_to_dec "$cleaned")
            for num in $vals; do printf "%03o " "$num"; done | sed 's/ $//' 
            ;;
        bin.base32) bin_to_ascii "$cleaned" | base32 ;;
        bin.base64) bin_to_ascii "$cleaned" | base64 ;;
        bin.unicode) bin_to_ascii "$cleaned" | ascii_to_unicode ;;
        bin.url) bin_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Decimal Conversions
        dec.ascii) dec_to_ascii "$cleaned" ;;
        dec.hex) dec_to_hex "$cleaned" ;;
        dec.bin) dec_to_bin "$cleaned" ;;
        dec.dec) echo "$cleaned" ;;
        dec.oct) for num in $cleaned; do printf "%03o " "$num"; done | sed 's/ $//' ;;
        dec.base32) dec_to_ascii "$cleaned" | base32 ;;
        dec.base64) dec_to_ascii "$cleaned" | base64 ;;
        dec.unicode) dec_to_ascii "$cleaned" | ascii_to_unicode ;;
        dec.url) dec_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Octal Conversions
        oct.ascii) oct_to_ascii "$cleaned" ;;
        oct.hex) for num in $cleaned; do printf "%02x" "0$num"; done ;;
        oct.bin) oct_to_bin "$cleaned" ;;
        oct.dec) for num in $cleaned; do printf "%d " "0$num"; done | sed 's/ $//' ;;
        oct.oct) echo "$cleaned" ;;
        oct.base32) oct_to_ascii "$cleaned" | base32 ;;
        oct.base64) oct_to_ascii "$cleaned" | base64 ;;
        oct.unicode) oct_to_ascii "$cleaned" | ascii_to_unicode ;;
        oct.url) oct_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Base32 Conversions
        base32.ascii) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True).decode(errors='ignore'), end='')" 2>/dev/null ;;
        base32.hex) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True).hex(), end='')" 2>/dev/null ;;
        base32.bin) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(''.join(format(x, '08b') for x in d), end='')" 2>/dev/null ;;
        base32.dec) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join(str(x) for x in d), end='')" 2>/dev/null
            ;;
        base32.oct) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join(format(x, '03o') for x in d), end='')" 2>/dev/null
            ;;
        base32.base64) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(base64.b64encode(d).decode(), end='')" 2>/dev/null ;;
        base32.unicode) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join([f'U+{x:04X}' for x in d]), end='')" 2>/dev/null ;;
        base32.url) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(''.join(['%' + format(x, '02x') for x in d]), end='')" 2>/dev/null ;;
        base32.base32) echo "$cleaned" ;;

        # Base64 Conversions
        base64.ascii) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b64decode(b + '=' * (4 - len(b) % 4)).decode(errors='ignore'), end='')" 2>/dev/null ;;
        base64.hex) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b64decode(b + '=' * (4 - len(b) % 4)).hex(), end='')" 2>/dev/null ;;
        base64.bin) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(''.join(format(x, '08b') for x in d), end='')" 2>/dev/null ;;
        base64.dec) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join(str(x) for x in d), end='')" 2>/dev/null
            ;;
        base64.oct) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join(format(x, '03o') for x in d), end='')" 2>/dev/null
            ;;
        base64.base32) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(base64.b32encode(d).decode(), end='')" 2>/dev/null ;;
        base64.unicode) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join([f'U+{x:04X}' for x in d]), end='')" 2>/dev/null ;;
        base64.url) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(''.join(['%' + format(x, '02x') for x in d]), end='')" 2>/dev/null ;;
        base64.base64) echo "$cleaned" ;;
        
        # URL Conversions
        url.ascii) printf "%b" "$cleaned" ;;
        url.hex) printf "%b" "$cleaned" | xxd -p ;;
        url.bin) printf "%b" "$cleaned" | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n' ;;
        url.dec) 
            hexs=$(printf "%b" "$cleaned" | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%d " "0x$hex"; done | sed 's/ $//' 
            ;;
        url.oct) 
            hexs=$(printf "%b" "$cleaned" | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%03o " "0x$hex"; done | sed 's/ $//' 
            ;;
        url.base32) printf "%b" "$cleaned" | base32 ;;
        url.base64) printf "%b" "$cleaned" | base64 ;;
        url.unicode) printf "%b" "$cleaned" | ascii_to_unicode ;;
        url.url) echo "$input" ;;
        
        # Unicode Conversions
        unicode.ascii) unicode_to_ascii "$cleaned" ;;
        unicode.hex) unicode_to_ascii "$cleaned" | ascii_to_hex ;;
        unicode.bin) unicode_to_ascii "$cleaned" | ascii_to_bin ;;
        unicode.dec) unicode_to_ascii "$cleaned" | ascii_to_dec ;;
        unicode.oct) unicode_to_ascii "$cleaned" | ascii_to_oct ;;
        unicode.base32) unicode_to_ascii "$cleaned" | base32 ;;
        unicode.base64) unicode_to_ascii "$cleaned" | base64 ;;
        unicode.url) unicode_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        unicode.unicode) echo "$input" ;;
        
        rot13.ascii) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        rot13.rot13) echo "$input" ;;

        # Hashes (Direct from ASCII/Bytes)
        ascii.md5) hash_string "$input" "md5" ;;
        ascii.sha1) hash_string "$input" "sha1" ;;
        ascii.sha256) hash_string "$input" "sha256" ;;
        ascii.sha384) hash_string "$input" "sha384" ;;
        ascii.sha512) hash_string "$input" "sha512" ;;
        ascii.crc32) hash_string "$input" "crc32" ;;

        # Hashes (from Hex Interpretation)
        hex.md5) hash_hex "$cleaned" "md5" ;;
        hex.sha1) hash_hex "$cleaned" "sha1" ;;
        hex.sha256) hash_hex "$cleaned" "sha256" ;;
        hex.sha384) hash_hex "$cleaned" "sha384" ;;
        hex.sha512) hash_hex "$cleaned" "sha512" ;;
        hex.crc32) hash_hex "$cleaned" "crc32" ;;
        
        *) 
            # PIVOT LOGIC: If explicit conversion not defined, try pivoting through ASCII
            # Condition: From != ascii AND To != ascii
            if [ "$from" != "ascii" ] && [ "$to" != "ascii" ]; then
                # 1. Convert From -> Ascii
                local ascii_temp
                { ascii_temp=$(perform_conversion "$input" "$from" "ascii"); } 2>/dev/null
                if [ $? -eq 0 ] && [ -n "$ascii_temp" ]; then
                     # 2. Convert Ascii -> To
                     perform_conversion "$ascii_temp" "ascii" "$to"
                     return $?
                fi
            fi
            return 1 
            ;;
    esac
}

# Main conversion router
convert() {
    local input="$1"
    local from="$2"
    local to="$3"
    
    from=$(normalize_format "$from")
    to=$(normalize_format "$to")
    
    # Clean input based on from format
    local cleaned=$(clean_input "$input" "$from")
    
    # Handle ALL options
    if [ "$to" == "all" ]; then
        echo -e "${PURPLE}┌──────────────────────────────────────────────────${NC}"
        echo -e "${PURPLE}│${NC} ${BOLD}Converting  ${NC} : ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}ALL${NC}"
        echo -e "${PURPLE}│${NC} ${BOLD}Source Input${NC} : ${YELLOW}$input${NC}"
        echo -e "${PURPLE}├──────────────────────────────────────────────────${NC}"
        echo ""
        
        if [ "$from" == "hex" ]; then
            hex_rep="$cleaned"
        else
            # Derive hex representation for safe hashing of potential null bytes
            hex_rep=$(perform_conversion "$input" "$from" "hex" 2>/dev/null)
        fi
        
        # 1. Semantic Encoders / Interpreted (INTERPRETED from decoded value)
        echo -e "${BOLD}${PURPLE}┌── Interpreted Conversions (Decoded Value)${NC}"
        for fmt in ascii unicode utf8 utf16 utf32; do
             # Always show interpreted results for clarity, especially ASCII
             { res=$(perform_conversion "$hex_rep" "hex" "$fmt"); } 2>/dev/null
             
             if [ $? -eq 0 ] && [ -n "$res" ]; then
                 printf "${PURPLE}│${NC}  ${CYAN}▸ %-10s${NC} : ${GREEN}%s${NC}\n" "$fmt" "$res"
             fi
        done

        echo -e "${PURPLE}├──────────────────────────────────────────────────${NC}"
        # 2. Standard Transformations (DIRECT from original input string)
        echo -e "${BOLD}${PURPLE}├── Direct Transformations (Literal String)${NC}"
        for fmt in hex bin dec oct base32 base64 url rot13 md5 sha1 sha256 sha384 sha512 crc32; do
             if [ "$fmt" == "$from" ]; then continue; fi
             
             # Direct (Input string characters)
             if [ "$fmt" == "rot13" ]; then
                 res=$(echo -n "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m')
             elif [ "$fmt" == "hex" ]; then
                 res=$(ascii_to_hex "$input")
             elif [ "$fmt" == "bin" ]; then
                 res=$(ascii_to_bin "$input")
             elif [ "$fmt" == "dec" ]; then
                 res=$(ascii_to_dec "$input")
             elif [ "$fmt" == "oct" ]; then
                 res=$(ascii_to_oct "$input")
             elif [ "$fmt" == "base32" ]; then
                 res=$(echo -n "$input" | base32 | tr -d '\n')
             elif [ "$fmt" == "base64" ]; then
                 res=$(echo -n "$input" | base64 | tr -d '\n')
             elif [ "$fmt" == "url" ]; then
                 res=$(echo -n "$input" | xxd -p | sed 's/../%&/g')
             elif [[ "$fmt" =~ ^(md5|sha1|sha256|sha384|sha512|crc32)$ ]]; then
                 res=$(hash_string "$input" "$fmt")
             else
                 { res=$(perform_conversion "$input" "ascii" "$fmt"); } 2>/dev/null
             fi
             
             if [ $? -eq 0 ] && [ -n "$res" ]; then
                 printf "${PURPLE}│${NC}  ${CYAN}▸ %-10s${NC} : ${GREEN}%s${NC}\n" "$fmt" "$res"
             fi
        done
        echo -e "${PURPLE}└──────────────────────────────────────────────────${NC}"
        
        return 0
    fi

    # Handle Standard/Single Conversion
    if [[ "$to" =~ ^(ascii|unicode|utf8|utf16|utf32)$ ]]; then
        local result=$(perform_conversion "$input" "$from" "$to")
        if [ $? -eq 0 ]; then
            echo -e "${PURPLE}┌── Converting: ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}$to${NC} ${YELLOW}(Interpreted)${NC}"
            echo -e "${PURPLE}│${NC}  ${CYAN}Input  ${NC} : ${YELLOW}$input${NC}"
            echo -e "${PURPLE}└─${NC} ${CYAN}Output ${NC} : ${BOLD}${GREEN}$result${NC}"
            return 0
        fi
    else
        # DIRECT (Treat input as literal string)
        # We pivot through 'ascii' to use our standard transformation functions
        local result=$(perform_conversion "$input" "ascii" "$to")
        if [ $? -eq 0 ]; then
            echo -e "${PURPLE}┌── Converting: ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}$to${NC} ${YELLOW}(Direct)${NC}"
            echo -e "${PURPLE}│${NC}  ${CYAN}Input  ${NC} : ${YELLOW}$input${NC}"
            echo -e "${PURPLE}└─${NC} ${CYAN}Output ${NC} : ${BOLD}${GREEN}$result${NC}"
            return 0
        fi
    fi
     
    echo -e "${RED}Unsupported conversion: $from → $to${NC}"
    echo -e "${YELLOW}Supported formats:${NC}"
    echo "  hex, ascii, bin, dec, oct, base32, base64, url, unicode, rot13"
    echo "  Encoders: utf8, utf16, utf32"
    echo "  Hashes: md5, sha1, sha256, sha384, sha512, crc32"
    return 1
}

# Show banner
show_banner() {
    echo -e " "
    echo -e "  ${PURPLE}      *           .                    *          .         ${NC}"
    echo -e "  ${PURPLE}           .              .           .            *    ${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██████╗ ██████╗ ██╗███████╗███╗   ███╗${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██╔══██╗██╔══██╗██║██╔════╝████╗ ████║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██████╔╝██████╔╝██║███████╗██╔████╔██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██║     ██║  ██║██║███████║██║ ╚═╝ ██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝${NC}"
    echo -e "  ${PURPLE}             .        .         .        .         *    ${NC}"
    echo -e " "
    echo -e "                ${BOLD}${PURPLE}─ Convert Your Data to Any Format ─${NC}"
    echo -e "    ${PURPLE}─────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

# Show help
show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 <input> <from> <to>       Standard conversion"
    echo "  $0 <input> <from> all        Bulk conversion (Shows all formats)"
    echo "  $0 <input> all               Auto-detect format & bulk convert"
    echo "  $0 <input>                   Auto-detect format & show text"
    echo ""
    echo -e "${CYAN}Formats:${NC}"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Standards:"   "hex, ascii, bin, dec, oct, b32, b64, url, rot13"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Encoders:"    "utf8, utf16, utf32, unicode (U+XXXX)"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Hashes:"      "md5, sha1, sha256, sha384, sha512, crc32"
    echo ""
    echo -e "${CYAN}Logical Layers:${NC}"
    echo -e "  ${YELLOW}Direct:${NC}      Treats your input as literal characters (Direct transformations)."
    echo -e "               (Includes: standard transforms, rot13, and hashes)"
    echo -e "  ${YELLOW}Interpreted:${NC} Decodes your input first, then transforms the meaning."
    echo -e "               (Includes: ascii, unicode, utf8/16/32)"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo "  - Intelligent Auto-detection of encoding types."
    echo "  - Reliable Hex-pivot ensures binary integrity (Null-byte safe)."
    echo "  - 'all' mode shows both literal and semantic derivations."
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 cGljb... b64 all         (Bulk convert Base64 flag)"
    echo "  $0 414243 hex md5            (Hash the hex string characters)"
    echo "  $0 \"A\" ascii utf16           (Convert character A to UTF-16 Hex)"
    echo "  $0 01100001 bin ascii        (Convert binary to text)"
    echo ""
}

# Main
check_dependencies
show_banner
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Auto-detect format if only input given

# Helper to detect format
detect_format() {
    local input="$1"
    
    # URL encoded (distinctive %)
    if [[ "$input" =~ %[0-9a-fA-F][0-9a-fA-F] ]]; then
        echo "url"
    # Unicode (U+...)
    elif [[ "$input" =~ U\+[0-9a-fA-F]+ ]]; then
        echo "unicode"
    # Binary (0 and 1 only)
    elif [[ "$input" =~ ^[01\ ]+$ ]]; then
        echo "bin"
    # Decimal (0-9 only)
    elif [[ "$input" =~ ^[0-9\ ]+$ ]]; then
        echo "dec"
    # Hex (0-9, a-f) - Checked AFTER binary/decimal
    elif [[ "$input" =~ ^[0-9a-fA-F\ ]+$ ]] || [[ "$input" =~ ^0x[0-9a-fA-F]+$ ]]; then
        echo "hex"
    # Base32 (A-Z, 2-7)
    elif [[ "$input" =~ ^[A-Z2-7\ ]+={0,6}$ ]]; then
        echo "base32"
    # Base64
    elif [[ "$input" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
        echo "base64"
    else
        echo "ascii"
    fi
}


if [ $# -eq 1 ]; then
    echo -e "${YELLOW}Auto-detecting format...${NC}"
    input="$1"
    
    fmt=$(detect_format "$input")
    if [ "$fmt" == "ascii" ]; then
        # Fallback view all
        echo -e "${YELLOW}Assuming ASCII text. Conversions:${NC}"
        echo "  hex:    $(convert "$input" ascii hex 2>/dev/null)"
        echo "  binary: $(convert "$input" ascii bin 2>/dev/null)"
        echo "  decimal: $(convert "$input" ascii dec 2>/dev/null)"
        echo "  octal:  $(convert "$input" ascii oct 2>/dev/null)"
        echo "  base32: $(convert "$input" ascii base32 2>/dev/null)"
        echo "  base64: $(convert "$input" ascii base64 2>/dev/null)"
        echo "  URL:    $(convert "$input" ascii url 2>/dev/null)"
        echo "  Unicode: $(convert "$input" ascii unicode 2>/dev/null)"
    else
        convert "$input" "$fmt" ascii
    fi
    exit 0
fi

# Handle 2 arguments as: convert <input> <to_hash> OR convert <input> all
if [ $# -eq 2 ]; then
    target=$(normalize_format "$2")
    
    # Check if second arg is "all"
    if [ "$target" == "all" ]; then
        # AUTO-DETECT input format for "all" command!
        # Do not assume ASCII automatically.
        detected=$(detect_format "$1")
        echo -e "${YELLOW}Auto-detected input format: $detected${NC}"
        convert "$1" "$detected" "all"
        exit 0
    fi

    #Check if second arg is a hash
    if [[ "$target" =~ ^(md5|sha1|sha256|sha384|sha512|crc32)$ ]]; then
        input="$1"
        echo -e "${CYAN}Hashing: '$input' → $target${NC}"
        echo -e "${GREEN}Output: $(hash_string "$input" "$target")${NC}"
        echo ""
        exit 0
    fi
     
    # If not a hash, it might be an invalid usage of convert <input> <from>??
    # Or convert <input> <to> assuming ascii? Let's stick to user request for hashes only for now.
    echo -e "${RED}Error: Invalid arguments for conversion. Did you mean to hash?${NC}"
    show_help
    exit 1
fi

# Full conversion
if [ $# -eq 3 ]; then
    # Special Check: If target is hash, treat it as hashing only if from is ascii or compatible
    # Actually, keep strictly to the logic: convert <input> <from> <to>
    # If 'to' is a hash, we pass it to convert(), which handles it in the default case if not matched
    
    convert "$1" "$2" "$3"
    exit 0
fi

echo -e "${RED}Error: Invalid number of arguments${NC}"
show_help
exit 1
