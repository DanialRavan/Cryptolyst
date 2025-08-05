import os
import re
import decoders

# Configuration
VOCABULARY_PATH = "vocabulary"
PLAUSIBILITY_THRESHOLD = 70.0

# Analysis
def load_vocabulary(folder_path):
    word_set = set()
    if not os.path.isdir(folder_path):
        print(f"Warning: Vocabulary directory '{folder_path}' not found.")
        return word_set
    
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            try:
                with open(os.path.join(folder_path, filename), 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word_set.add(line.strip().lower())
            except IOError as e:
                print(f"Warning: Could not read file {filename}: {e}")
    return word_set

def segment_words(text, dictionary):
    if not text:
        return ""
    for i in range(len(text), 0, -1):
        prefix = text[:i]
        if prefix in dictionary:
            suffix = text[i:]
            segmented_suffix = segment_words(suffix, dictionary)
            if segmented_suffix is not None:
                return prefix + (" " + segmented_suffix if segmented_suffix else "")
    return None

def calculate_word_accuracy(text, dictionary):
    if not dictionary or not text or not isinstance(text, str):
        return 0.0
    
    words = [word for word in re.findall(r'[a-zA-Z]{2,}', text.lower())]
    
    if not words and ' ' not in text and len(text) > 10:
        sanitized = ''.join(c for c in text.lower() if c.isalpha())
        segmented_text = segment_words(sanitized, dictionary)
        if segmented_text:
            words = [word for word in segmented_text.split() if len(word) > 1]

    if not words:
        return 0.0
    
    recognized_words = sum(1 for word in words if word in dictionary)
    return (recognized_words / len(words)) * 100

# Main
def main():
    ciphertext = input("Please enter the ciphertext to decode: ")

    all_results = decoders.run_decoders(ciphertext)
    dictionary = load_vocabulary(VOCABULARY_PATH)

    plausible_results = []
    for result in all_results:
        accuracy = calculate_word_accuracy(result['output'], dictionary)
        if accuracy >= PLAUSIBILITY_THRESHOLD:
            result['accuracy'] = accuracy
            plausible_results.append(result)

    if not plausible_results:
        print("\nNo plausible results found.")
    else:
        print("\nFound plausible results:")
        plausible_results.sort(key=lambda x: (x['accuracy'], x['output'].count(' '), len(x['output'])), reverse=True)
        for result in plausible_results:
            config = result.get('config')
            if config and config.strip():
                print(f"{result['accuracy']:.0f}% | {result['name']} ({config}): {result['output']}")
            else:
                print(f"{result['accuracy']:.0f}% | {result['name']}: {result['output']}")

if __name__ == "__main__":
    main()