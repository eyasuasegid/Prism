
# Universal Converter CLI Tool

A powerful command-line tool for converting between multiple data formats including hexadecimal, ASCII, binary, decimal, octal, Base64, URL encoding, and ROT13.

## Features

- 🔄 **Bidirectional Conversions**: Convert between any supported formats
- 🤖 **Auto-detection**: Intelligent format detection from input
- 🎨 **Colorful Terminal Output**: Easy-to-read colored interface
- 📱 **Flexible Input**: Accepts various input formats (spaces, prefixes, etc.)
- ⚡ **Fast & Efficient**: Uses built-in Linux tools for optimal performance
- 🔧 **Simple Interface**: Clean command-line interface

## Installation

### Prerequisites
- Bash 4.0 or higher
- Standard Unix utilities: `xxd`, `base64`, `bc`
- Python 3 (optional, for fallback conversions)



### Installation
```bash
git clone https://github.com/username/universal-converter.git
cd universal-converter
chmod +x converter.sh
```

## Usage

### Basic Syntax
```bash
convert <input> [from_format] [to_format]
```

### Operation Modes

#### Auto-detect Mode
The tool automatically detects the input format and converts to ASCII:
```bash
convert "6579617375"            # Detects hex, outputs "eyasu"
convert "hello world"           # Detects ASCII, shows all conversions
convert "01110000"              # Detects binary, outputs "p"
```

#### Explicit Conversion
Specify both source and target formats:
```bash
convert "7069636f" hex ascii    # Hexadecimal → ASCII
convert "hello" ascii hex       # ASCII → Hexadecimal
convert "01110000" bin hex      # Binary → Hexadecimal
convert "112 105 99" dec ascii  # Decimal → ASCII
```

#### Short Format Names
Use abbreviated format names for quick conversions:
```bash
convert "70" h a                # hex → ascii
convert "p" a h                 # ascii → hex6579617375
convert "01110000" b h          # binary → hex
convert "112" d h               # decimal → hex
convert "160" o h               # octal → hex
```

## Supported Formats

| Format | Short Name | Example Input |
|--------|------------|---------------|
| **Hexadecimal** | `hex`, `h` | `7069636f`, `0x70`, `70 69` |
| **ASCII** | `ascii`, `a` | `hello`, `test123` |
| **Binary** | `bin`, `b` | `01110000`, `0110 1001` |
| **Decimal** | `dec`, `d` | `112 105 99`, `11210599111` |
| **Octal** | `oct`, `o` | `160 151 143`, `777` |
| **Base64** | `base64`, `b64` | `aGVsbG8=` |
| **URL Encoding** | `url` | `%68%65%6c%6c%6f` |
| **ROT13** | `rot13`, `rot` | `uryyb` |

## Examples

### Common Conversions
```bash
# Hexadecimal conversions
convert "48656c6c6f" hex ascii          # Output: Hello
convert "Hello" ascii hex               # Output: 48656c6c6f

# Binary conversions
convert "0110100001100101011011000110110001101111" bin ascii  # Output: hello

# Decimal conversions
convert "72 101 108 108 111" dec ascii  # Output: Hello

# Base64 conversions
convert "SGVsbG8=" base64 ascii         # Output: Hello

# URL encoding conversions
convert "%48%65%6c%6c%6f" url ascii     # Output: Hello

# ROT13 conversions
convert "Uryyb" rot13 ascii             # Output: Hello
```

### Advanced Usage
```bash
# Chain conversions using pipes
echo "48656c6c6f" | xargs convert hex ascii

# Convert files
convert "$(cat data.txt)" hex ascii

# Multiple values with spaces
convert "72 101 108 108 111" dec ascii

# Hexadecimal with 0x prefix
convert "0x48 0x65 0x6c 0x6c 0x6f" hex ascii

# Mixed formatting
convert "48 65 6c 6c 6f" hex ascii      # Spaces allowed
convert "48-65-6c-6c-6f" hex ascii      # Dashes removed
```

## Troubleshooting

### Common Issues

1. **No output or empty output**
   ```bash
   # Add newline
   convert "70" hex ascii && echo
   
   # Check for invisible characters
   convert "70" hex ascii | cat -A
   ```

2. **"Unsupported conversion" error**
   - Verify format names are correct
   - Check available formats with `convert` (no arguments)

3. **Odd-length hexadecimal strings**
   - Automatically padded with leading zero
   - Example: `"f"` becomes `"0f"`

4. **Binary strings not multiple of 8**
   - Automatically padded with leading zeros
   - Example: `"101"` becomes `"00000101"`
