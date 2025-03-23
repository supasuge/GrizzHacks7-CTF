import string
import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Any
import re
import threading
from queue import Queue
import concurrent.futures
from statistics import mean
import time

@dataclass
class Term:
    """ANSI terminal colors for pretty output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

@dataclass
class DecryptionResult:
    """Store decryption attempt results"""
    key_length: int
    key: str
    decrypted: str
    formatted: str
    flag: Optional[str]
    score: float
    ioc_score: float
    kasiski_score: float
    frequency_score: float

class CiphertextParser:
    """Parser for extracting multiple ciphertexts from a file"""
    
    @staticmethod
    def clean_text(text: str) -> str:
        """Clean raw text by removing extra whitespace and quotes"""
        text = text.replace('"""', '').strip()
        return text
        
    def parse_file(self, filename: str) -> list[str]:
        """Parse file containing multiple ciphertexts"""
        ciphertexts = []
        current_text = []
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                
                if not line and not current_text:
                    continue
                    
                if line.startswith('"""'):
                    if current_text:
                        text = '\n'.join(current_text)
                        ciphertexts.append(self.clean_text(text))
                        current_text = []
                    current_text.append(line)
                    
                elif current_text:
                    current_text.append(line)
                    
            if current_text:
                text = '\n'.join(current_text)
                ciphertexts.append(self.clean_text(text))
                
            return ciphertexts
            
        except FileNotFoundError:
            print(f"{Term.RED}Error: File {filename} not found{Term.END}")
            return []
        except Exception as e:
            print(f"{Term.RED}Error parsing file: {str(e)}{Term.END}")
            return []

class VigenereSolver:
    def __init__(self):
        self.english_freqs = {
            'A': 0.0855, 'B': 0.0160, 'C': 0.0316, 'D': 0.0387, 'E': 0.1210,
            'F': 0.0218, 'G': 0.0209, 'H': 0.0496, 'I': 0.0733, 'J': 0.0022,
            'K': 0.0081, 'L': 0.0421, 'M': 0.0253, 'N': 0.0717, 'O': 0.0747,
            'P': 0.0207, 'Q': 0.0010, 'R': 0.0633, 'S': 0.0673, 'T': 0.0894,
            'U': 0.0268, 'V': 0.0106, 'W': 0.0183, 'X': 0.0019, 'Y': 0.0172,
            'Z': 0.0011
        }
        
        self.english_bigrams = {
            'TH': 0.0271, 'HE': 0.0233, 'IN': 0.0203, 'ER': 0.0178, 'AN': 0.0161,
            'RE': 0.0141, 'ND': 0.0131, 'AT': 0.0120, 'ON': 0.0117, 'NT': 0.0113
        }
        
        self.flag_patterns = [
            
            re.compile(r'GRIZZCTF.*FLAG'),
            
        ]
        
        self.stats = {
            'start_time': None,
            'attempts': 0,
            'best_ioc': 0,
            'best_kasiski': 0
        }

    def calculate_ioc(self, text: str) -> float:
        """Calculate Index of Coincidence"""
        n = len(text)
        if n <= 1:
            return 0
        freqs = Counter(text)
        sum_fi_2 = sum(freq * (freq - 1) for freq in freqs.values())
        return sum_fi_2 / (n * (n - 1))

    def find_key_char(self, text: str) -> Tuple[str, float]:
        """Find single character of key using frequency analysis"""
        best_shift = 0
        best_score = float('inf')
        
        for shift in range(26):
            shifted_text = ''.join(
                chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                for c in text
            )
            score = self.frequency_analysis(shifted_text)
            if score < best_score:
                best_score = score
                best_shift = shift
        
        return chr(best_shift + ord('A')), best_score

    def find_key(self, text: str, key_length: int) -> Tuple[str, float]:
        """Find complete key of given length"""
        key = ""
        total_score = 0
        
        cosets = [''.join(text[i::key_length]) for i in range(key_length)]
        
        for coset in cosets:
            char, score = self.find_key_char(coset)
            key += char
            total_score += score
        
        return key, total_score / key_length

    def decrypt(self, text: str, key: str) -> str:
        """Decrypt text using Vigenère cipher"""
        plaintext = ""
        key_length = len(key)
        key_idx = 0
        
        for char in text:
            if char.isalpha():
                p = ord(char.upper()) - ord('A')
                k = ord(key[key_idx % key_length]) - ord('A')
                c = (p - k) % 26
                plaintext += chr(c + ord('A'))
                key_idx += 1
            else:
                plaintext += char
                
        return plaintext

    def frequency_analysis(self, text: str) -> float:
        """Perform frequency analysis"""
        freqs = Counter(filter(str.isalpha, text))
        text_length = sum(freqs.values())
        if text_length == 0:
            return float('inf')
            
        chi_squared = 0.0
        for letter in string.ascii_uppercase:
            observed = freqs.get(letter, 0)
            expected = self.english_freqs[letter] * text_length
            chi_squared += (observed - expected) ** 2 / (expected if expected != 0 else 0.0001)
                
        return chi_squared

    def extract_flag(self, text: str) -> Optional[str]:
        """Extract flag from decrypted text"""
        for pattern in self.flag_patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    def _get_factors(self, n: int) -> List[int]:
        """Get all factors of a number within reasonable key length range"""
        factors = []
        for i in range(1, min(31, n + 1)):
            if n % i == 0 and i <= 30:
                factors.append(i)
        return factors

    def kasiski_examination(self, text: str) -> List[int]:
        """Kasiski examination to find potential key lengths"""
        sequences = {}
        for length in range(3, 6):
            for i in range(len(text) - length):
                seq = text[i:i+length]
                if seq.isalpha():
                    if seq in sequences:
                        sequences[seq].append(i)
                    else:
                        sequences[seq] = [i]

        distances = []
        for positions in sequences.values():
            if len(positions) >= 2:
                for i in range(len(positions) - 1):
                    distance = positions[i + 1] - positions[i]
                    if distance > 5:
                        distances.append(distance)

        if not distances:
            return list(range(6, 31, 2))

        factors = []
        for d in distances:
            factors.extend(self._get_factors(d))

        factor_counts = Counter(factors)
        possible_lengths = [
            length for length, count in factor_counts.most_common()
            if 6 <= length <= 30 and count >= 2
        ]

        return possible_lengths[:5] if possible_lengths else list(range(6, 31, 2))

    def parse_text(self, text: str) -> Tuple[List[Tuple[str, str]], str]:
        """Parse text preserving format"""
        parsed = []
        cleaned = []
        
        for char in text:
            if char.isalpha():
                parsed.append((char, 'letter'))
                cleaned.append(char.upper())
            elif char.isspace():
                parsed.append((char, 'space'))
            else:
                parsed.append((char, 'punctuation'))
                
        return parsed, ''.join(cleaned)

    def format_result(self, parsed: List[Tuple[str, str]], decrypted: str) -> str:
        """Format decrypted text preserving original format"""
        result = []
        dec_idx = 0
        
        for char, char_type in parsed:
            if char_type == 'letter':
                result.append(decrypted[dec_idx])
                dec_idx += 1
            else:
                result.append(char)
                
        return ''.join(result)

    def _print_progress(self, result: DecryptionResult):
        """Print progress update"""
        print(f"\n{Term.YELLOW}New best result found:{Term.END}")
        print(f"Key length: {result.key_length}")
        print(f"Key: {result.key}")
        print(f"Score: {result.score:.4f}")
        if result.flag:
            print(f"{Term.GREEN}Flag found: {result.flag}{Term.END}")
    
    def correct_word(self, word: str) -> str:
        """Attempt to correct a potentially mistyped word using common patterns"""
        common_substitutions = {
            'U': 'O', 'O': 'U',  # Common O/U confusion
            'I': 'L', 'L': 'I',  # Common I/L confusion
            'B': 'R', 'R': 'B',  # Common B/R confusion
            'N': 'M', 'M': 'N',  # Common M/N confusion 
            'H': 'N', 'N': 'H',  # Common H/N confusion
            'E': 'F', 'F': 'E',  # Common E/F confusion
            'S': 'G', 'G': 'S',  # Common S/G confusion
            'P': 'R', 'R': 'P'   # Common P/R confusion
        }
        
        # Dictionary of known correct words
        known_words = {
            'GRIZZCTF': True,
            'FLAG': True
        }
        
        # Check if word is already correct
        if word in known_words:
            return word if known_words[word] is True else known_words[word]
            
        # Try substitutions
        for orig, repl in common_substitutions.items():
            if orig in word:
                corrected = word.replace(orig, repl)
                if corrected in known_words:
                    return corrected if known_words[corrected] is True else known_words[corrected]
                    
        return word
    
    def post_process_text(self, text: str) -> str:
        """Apply post-processing error correction to decrypted text"""
        words = text.split()
        corrected_words = []
        
        for word in words:
            # Only try to correct alphabetic words
            if word.isalpha():
                corrected = self.correct_word(word)
                corrected_words.append(corrected)
            else:
                corrected_words.append(word)
                
        return ' '.join(corrected_words)
    def calculate_text_score(self, text: str) -> float:
        """Calculate comprehensive text quality score"""
        # Check letter frequencies
        freq_score = self.frequency_analysis(text)
        
        # Check Index of Coincidence
        ioc = self.calculate_ioc(text)
        
        # Count recognizable English words
        words = text.split()
        word_score = sum(1 for word in words if self.correct_word(word) == word) / len(words)
        
        # Weight the components
        score = (
            0.4 * freq_score +      # Letter frequency match
            0.4 * (1 - ioc) +       # Index of Coincidence (closer to English)
            0.2 * (1 - word_score)  # Recognizable word ratio
        )
        
        return score

    def try_key_length(self, text: str, length: int, parsed: List[Tuple[str, str]]) -> DecryptionResult:
        """Try decryption with specific key length and error correction"""
        key, freq_score = self.find_key(text, length)
        decrypted = self.decrypt(text, key)
        
        # Apply error correction
        corrected = self.post_process_text(decrypted)
        
        # Calculate scores
        ioc = self.calculate_ioc(corrected)
        kasiski = len(self.kasiski_examination(corrected))
        final_score = self.calculate_text_score(corrected)
        
        return DecryptionResult(
            key_length=length,
            key=key,
            decrypted=corrected,  # Use corrected text
            formatted=self.format_result(parsed, corrected),
            flag=self.extract_flag(corrected),
            score=final_score,
            ioc_score=ioc,
            kasiski_score=kasiski,
            frequency_score=freq_score
        )

    def solve(self, ciphertext: str) -> DecryptionResult:
        """Main solving function"""
        self.stats['start_time'] = time.time()
        print(f"{Term.BOLD}Starting Vigenère cipher analysis...{Term.END}\n")

        parsed, cleaned_text = self.parse_text(ciphertext)
        print(f"{Term.CYAN}Text length: {len(cleaned_text)} characters{Term.END}")

        print(f"\n{Term.BOLD}Performing Kasiski examination...{Term.END}")
        kasiski_lengths = self.kasiski_examination(cleaned_text)
        
        test_lengths = set(kasiski_lengths + list(range(6, 31, 2)))
        print(f"{Term.CYAN}Testing key lengths: {sorted(test_lengths)}{Term.END}")

        best_result = None
        best_score = float('inf')

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for length in sorted(test_lengths):
                futures.append(executor.submit(self.try_key_length, cleaned_text, length, parsed))

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result.score < best_score:
                    best_score = result.score
                    best_result = result
                    self._print_progress(result)

        if best_result:
            print(f"\n{Term.GREEN}Analysis complete! Time taken: {time.time() - self.stats['start_time']:.2f}s{Term.END}")
            return best_result
        else:
            raise ValueError("No valid solution found")

def main():
    import sys
    if len(sys.argv) != 2:
        print(f"{Term.RED}Usage: python script.py <input_file>{Term.END}")
        sys.exit(1)

    filename = sys.argv[1]
    solver = VigenereSolver()
    parser = CiphertextParser()
    
    print(f"{Term.CYAN}Reading ciphertexts from file...{Term.END}")
    ciphertexts = parser.parse_file(filename)
    
    if not ciphertexts:
        print(f"{Term.RED}No ciphertexts found in file{Term.END}")
        return
        
    print(f"{Term.GREEN}Found {len(ciphertexts)} ciphertexts{Term.END}\n")
    correct = 0
    for i, ct in enumerate(ciphertexts, 1):
        print(f"\n{Term.BOLD}Processing Ciphertext {i}/{len(ciphertexts)}{Term.END}")
        print("-" * 80)
        
        try:
            result = solver.solve(ct)
            if result:
                print(f"\n{Term.GREEN}Results for Ciphertext {i}:{Term.END}")
                print(f"Key Length: {result.key_length}")
                print(f"Key: {result.key}")
                if result.flag:
                    # or at least close enough
                    correct += 1
                print(f"\n{Term.YELLOW}Flag Found:{Term.END} {result.flag}")
                print("\nDecrypted Text:")
                print(f"{correct}/{i}")
                print(result.formatted)
            else:
                print(f"{Term.RED}No valid solution found for ciphertext {i}{Term.END}")
            
        except Exception as e:
            print(f"{Term.RED}Error processing ciphertext {i}: {str(e)}{Term.END}")
            continue
            
        print("\n" + "=" * 80)

if __name__ == "__main__":
    main()