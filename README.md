# Cryptolyst

A command-line utility for identifying and decoding ciphers and text encodings, that leverages vocabulary-based analysis to evaluate potential decryptions and identify the most plausible result.

Co-authored by my friend, [Ariaa-H](https://github.com/Ariaa-H).

---

## Features
- Runs all supported decoders automatically.
- Brute-forces shift/key values where applicable.
- Cleans and detects various separators automatically.
- Uses dictionary-based scoring to rank plausible results.
- Supports multiple dictionaries to integrate more languages and/or precise vocabularies.

---

## Supported Ciphers and Encodings

| Cipher / Encoding | Category | Attack Method | Status |
| ----------------- | -------- | ------------- | :----: |
| **Affine Cipher** | Algorithmic & Brute-Force | Brute-force all valid `(a, b)` pairs | ✅ |
| **Caesar Cipher** | Algorithmic & Brute-Force | Brute-force all 25 shifts | ✅ |
| **ROT5 / ROT13 / ROT18 / ROT47** | Standard Decoder | Direct translation | ✅ |
| **ASCII85 / Base85** | Standard Decoder | Adobe & Standard decoding | ✅ |
| **Z85 (ZeroMQ Base85)** | Standard Decoder | ZeroMQ variant decoding | 🟡 |
| **Morse Code** | Standard Decoder | Dot-dash to text | ✅ |
| **Unicode** | Standard Decoder | Hex code points to text | ✅ |
| **Decimal** | Standard Decoder | Decimal values to text | ✅ |
| **Hexadecimal** | Standard Decoder | Hex values to text | ✅ |
| **Binary** | Standard Decoder | Binary (8-bit chunks) to text | ✅ |
| **Octal** | Standard Decoder | Octal values to text | ✅ |
| **NCR Decimal** | Standard Decoder | HTML numeric entities (decimal) | ✅ |
| **NCR Hexadecimal** | Standard Decoder | HTML numeric entities (hex) | ✅ |
| **Base32** *(Planned)* | Standard Decoder | Removed temporarily. | ❌ |
| **Base64** *(Planned)* | Standard Decoder | Removed temporarily. | ❌ |

**Status Key:** ✅ = Fully implemented | 🟡 = Experimental | ❌ = Not yet implemented

---

## Plausibility Ranking
The script evaluates decoded outputs against a vocabulary and assigns a *plausibility score* based on the percentage of recognized words. However, relying solely on this score can be misleading, as multiple decoding attempts might result in a high score but produce nonsensical gibberish.

For example, without a more advanced ranking system, the results might look like this:
```
100% | Base64 (RFC 3548, RFC 4648): \►DC (♫B►♦N`
100% | Base64url (RFC 4648 §5): \►DC :☻@‼☻☺:♥9
100% | Original Base64 (RFC 1421): \►DC (♫B►♦N`
100% | ASCII85 / Base85 (Standard): The quick brown fox jumps over the lazy dog.
```

To solve this, results that meet the **`PLAUSIBILITY_THRESHOLD`** (default: 70%) are then sorted using a more nuanced approach. The final ranking is based on three criteria in order of importance: the plausibility score, the number of spaces (favoring structured text), and the overall length. This ensures that human-readable text is prioritized over random characters, even if they have the same initial score.

With proper sorting logic, the same results are correctly ordered:
```
100% | ASCII85 / Base85 (Standard): The quick brown fox jumps over the lazy dog.
100% | Base64url (RFC 4648 §5): \►DC :☻@‼☻☺:♥9
100% | Base64 (RFC 3548, RFC 4648): \►DC (♫B►♦N`
100% | Original Base64 (RFC 1421): \►DC (♫B►♦N`
```

---

## Usage
```bash
python main.py
```
You will be prompted to paste your ciphertext.

**Example:**
```
Please enter the ciphertext to decode: Olssv, ovd hyl fvb kvpun?
```

**Output:**
```
Found plausible results:
100% | Caesar Cipher (Shift: 7): Hello, how are you doing?
100% | Affine Cipher (a=1, b=7): Hello, how are you doing?
```

---

## Folder Structure
```
.
├── decoders.py         # All decoding and brute-force functions.
├── main.py             # Entry point and plausibility ranking.
└── vocabulary/         # Wordlist text files for plausibility analysis.
```

---

## Vocabulary Files
The `vocabulary` folder should contain `.txt` files with one word per line. The quality of these wordlists directly impacts the accuracy of the plausibility score.

This project uses a customized and modified version of standard wordlists for improved performance and relevance. You can use any comprehensive wordlist, such as those derived from SCOWL.

---

## Credits
- **SCOWL & 12dicts** – For dictionary wordlists
  - Website: http://wordlist.aspell.net/
  - GitHub: https://github.com/en-wl/wordlist
