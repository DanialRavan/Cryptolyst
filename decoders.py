import string
import math
import re
from collections import Counter
from itertools import permutations

# Separator Detection
def _detect_and_remove_separators(text, valid_chars):
    text = re.sub(r'U\+|&#x|&#', '', text, flags=re.IGNORECASE)
    text = text.replace(';', ' ')

    temp_text = text
    valid_chars_upper = valid_chars.upper()
    for i in range(len(valid_chars)):
        temp_text = temp_text.replace(valid_chars[i], ' ')
        temp_text = temp_text.replace(valid_chars_upper[i], ' ')

    potential_separators = [word for word in temp_text.split(' ') if word]

    if not potential_separators:
        return ' '.join(text.split()), None

    separator_counts = Counter(potential_separators)
    most_common_separator = separator_counts.most_common(1)[0][0]

    cleaned_text = re.sub(re.escape(most_common_separator), ' ', text, flags=re.IGNORECASE)

    return ' '.join(cleaned_text.split()), most_common_separator

# Caesar Cipher
def _caesar_decrypt_char(char, shift):
    if char.isalpha():
        start = ord('a') if char.islower() else ord('A')
        return chr((ord(char) - start - shift + 26) % 26 + start)
    return char

def bruteforce_caesar(ciphertext):
    results = []
    for shift in range(1, 26):
        decrypted_text = "".join([_caesar_decrypt_char(char, shift) for char in ciphertext])
        results.append({
            'name': 'Caesar Cipher',
            'config': f'Shift: {shift}',
            'output': decrypted_text
        })
    return results

# Affine Cipher
def _mod_inverse(a, m):
    if math.gcd(a, m) != 1:
        return None
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def _affine_decrypt_char(char, a_inv, b):
    if char.isalpha():
        start = ord('a') if char.islower() else ord('A')
        y = ord(char) - start
        x = (a_inv * (y - b + 26)) % 26
        return chr(x + start)
    return char

def bruteforce_affine(ciphertext):
    results = []
    possible_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in possible_a:
        a_inv = _mod_inverse(a, 26)
        for b in range(26):
            decrypted_text = "".join([_affine_decrypt_char(char, a_inv, b) for char in ciphertext])
            results.append({
                'name': 'Affine Cipher',
                'config': f'a={a}, b={b}',
                'output': decrypted_text
            })
    return results

# ROT Ciphers
def decode_rot5(ciphertext):
    def _rot_char(char):
        if '0' <= char <= '9':
            return str((int(char) + 5) % 10)
        return char
    decrypted_text = "".join([_rot_char(c) for c in ciphertext])
    return [{
        'name': 'ROT5',
        'config': 'Digits',
        'output': decrypted_text
    }]

def decode_rot13(ciphertext):
    def _rot_char(char):
        if 'a' <= char <= 'z':
            return chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        if 'A' <= char <= 'Z':
            return chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        return char
    decrypted_text = "".join([_rot_char(c) for c in ciphertext])
    return [{
        'name': 'ROT13',
        'config': 'Letters',
        'output': decrypted_text
    }]

def decode_rot18(ciphertext):
    def _rot_char(char):
        if 'a' <= char <= 'z':
            return chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        if 'A' <= char <= 'Z':
            return chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        if '0' <= char <= '9':
            return str((int(char) + 5) % 10)
        return char
    decrypted_text = "".join([_rot_char(c) for c in ciphertext])
    return [{
        'name': 'ROT18',
        'config': 'Alphanumeric',
        'output': decrypted_text
    }]

def decode_rot47(ciphertext):
    def _rot_char(char):
        val = ord(char)
        if 33 <= val <= 126:
            return chr(33 + (val - 33 + 47) % 94)
        return char
    decrypted_text = "".join([_rot_char(c) for c in ciphertext])
    return [{
        'name': 'ROT47',
        'config': 'ASCII (!-~)',
        'output': decrypted_text
    }]

# ASCII85 / Base85
def decode_ascii85(ciphertext):
    results = []
    cleaned_text = ''.join(ciphertext.split())

    # Standard
    try:
        standard_decoded_bytes = base64.a85decode(cleaned_text.encode('ascii'), adobe=False)
        standard_decoded = standard_decoded_bytes.decode('utf-8', errors='ignore')
        
        if not any(r['output'] == standard_decoded for r in results):
            results.append({
                "name": "ASCII85 / Base85",
                "config": "Standard",
                "output": standard_decoded
            })
    except (ValueError, TypeError):
        pass

    # Adobe
    try:
        adobe_decoded_bytes = base64.a85decode(cleaned_text.encode('ascii'), adobe=True)
        adobe_decoded = adobe_decoded_bytes.decode('utf-8', errors='ignore')
        results.append({
            "name": "ASCII85 / Base85",
            "config": "Adobe",
            "output": adobe_decoded
        })
    except (ValueError, TypeError):
        pass

    return results

# Z85 / Base85
Z85_ALPHABET = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
Z85_DECODER = {c: i for i, c in enumerate(Z85_ALPHABET)}

def z85_decode(data: str) -> bytes:
    data = ''.join(data.split())
    if len(data) % 5 != 0:
        raise ValueError("Length of Z85 data must be multiple of 5")

    output = bytearray()
    for i in range(0, len(data), 5):
        value = 0
        for c in data[i:i+5]:
            value = value * 85 + Z85_DECODER[c]
        output.extend([
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ])
    return bytes(output)

def decode_z85(ciphertext):
    try:
        decoded_bytes = z85_decode(ciphertext)
        decoded = decoded_bytes.decode('utf-8', errors='ignore')
        return [{
            "name": "Z85 / Base85",
            "config": "ZeroMQ",
            "output": decoded
        }]
    except Exception:
        return []

# Morse Code
def decode_morse_code(ciphertext):
    MORSE_CODE_MAP = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' ', ' ': ' '
    }
    try:
        processed_text = re.sub(r'[^.\-/\s]', '', ciphertext)
        processed_text = processed_text.replace('/', ' / ')
        words = processed_text.strip().split(' / ')
        decoded_words = []
        for word in words:
            letters = word.strip().split()
            decoded_word = "".join(MORSE_CODE_MAP.get(letter, '') for letter in letters)
            decoded_words.append(decoded_word)
        decoded = " ".join(decoded_words)
        return [{
            "name": "Morse Code",
            "config": " ",
            "output": decoded
        }]
    except Exception:
        return []

# Unicode
def decode_unicode(ciphertext):
    try:
        cleaned, separator = _detect_and_remove_separators(ciphertext, string.hexdigits)
        decoded = ''.join(chr(int(c, 16)) for c in cleaned.split())
        config = f"Separator: '{separator}'" if separator else None
        return [{
            'name': 'Unicode',
            'config': config,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# Decimal
def decode_decimal(ciphertext):
    try:
        cleaned, separator = _detect_and_remove_separators(ciphertext, string.digits)
        if not cleaned: return []
        decoded = ''.join(chr(int(c)) for c in cleaned.split())
        config = f"Separator: '{separator}'" if separator else None
        return [{
            'name': 'Decimal',
            'config': config,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# Hexadecimal
def decode_hexadecimal(ciphertext):
    try:
        cleaned, separator = _detect_and_remove_separators(ciphertext, string.hexdigits)
        parts = cleaned.split()
        if any(len(p) % 2 != 0 for p in parts):
            cleaned = re.sub(r'\s+', '', cleaned)
            parts = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]

        decoded = bytes.fromhex(''.join(parts)).decode('utf-8', errors='ignore')
        config = f"Separator: '{separator}'" if separator else None
        return [{
            'name': 'Hexadecimal',
            'config': config,
            'output': decoded
        }]
    except ValueError:
        return []

# Binary
def decode_binary(ciphertext):
    try:
        cleaned, separator = _detect_and_remove_separators(ciphertext, '01')
        parts = cleaned.split()
        if len(parts) == 1 and len(parts[0]) > 8:
            parts = [parts[0][i:i+8] for i in range(0, len(parts[0]), 8)]

        decoded = ''.join(chr(int(b, 2)) for b in parts if b)
        config = f"Separator: '{separator}'" if separator else "8-bit Chunks"
        return [{
            'name': 'Binary',
            'config': config,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# Octal
def decode_octal(ciphertext):
    try:
        cleaned, separator = _detect_and_remove_separators(ciphertext, '01234567')
        if not cleaned: return []
        decoded = ''.join(chr(int(c, 8)) for c in cleaned.split())
        config = f"Separator: '{separator}'" if separator else None
        return [{
            'name': 'Octal',
            'config': config,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# NCR (Decimal)
def decode_ncr_decimal(ciphertext):
    try:
        matches = re.findall(r'&#(\d+);', ciphertext)
        format_used = '&#...;'
        if not matches:
            cleaned, separator = _detect_and_remove_separators(ciphertext, string.digits)
            if not cleaned: return []
            matches = cleaned.split()
            format_used = f"Separator: '{separator}'" if separator else None

        decoded = ''.join(chr(int(m)) for m in matches)
        return [{
            'name': 'NCR (Decimal)',
            'config': format_used,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# NCR (Hexadecimal)
def decode_ncr_hex(ciphertext):
    try:
        matches = re.findall(r'&#x([0-9a-fA-F]+);', ciphertext)
        format_used = '&#x...;'
        if not matches:
            cleaned, separator = _detect_and_remove_separators(ciphertext, string.hexdigits)
            if not cleaned: return []
            matches = cleaned.split()
            format_used = f"Separator: '{separator}'" if separator else None

        decoded = ''.join(chr(int(m, 16)) for m in matches)
        return [{
            'name': 'NCR (Hexadecimal)',
            'config': format_used,
            'output': decoded
        }]
    except (ValueError, OverflowError):
        return []

# Run all decoders
def run_decoders(ciphertext):
    decoders_to_run = [
        bruteforce_caesar,
        bruteforce_affine,
        decode_rot5,
        decode_rot13,
        decode_rot18,
        decode_rot47,
        decode_ascii85,
        decode_z85,
        decode_morse_code,
        decode_unicode,
        decode_decimal,
        decode_hexadecimal,
        decode_binary,
        decode_octal,
        decode_ncr_decimal,
        decode_ncr_hex,
    ]

    all_potential_results = []
    for decoder_func in decoders_to_run:
        try:
            all_potential_results.extend(decoder_func(ciphertext))
        except Exception:
            continue

    return all_potential_results