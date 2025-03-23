#!/usr/bin/env python3
"""
This script was written in a google colab Jupyter Notebook and is meant to be used and perform the training of the model rather than performing it locally.

This script performs the following steps:
  1. Downloads and combines a large corpus from NLTK’s Gutenberg and WordNet collections
     (improving diversity).
  2. Generates a synthetic dataset by selecting random segments of the corpus, encrypting them
     with randomly generated Vigenère keys (with key lengths 3–50), and extracting a 77-dimensional
     feature vector from each ciphertext.
  3. Trains a hybrid ensemble feedforward neural network on the synthetic data.
  4. Saves the trained model in the new “.keras” format and also pickles a KeyLengthPredictor object,
     which can later be imported in a local library.

This script will take ~24hr to complete the full generation of the synthetic vigenere ciphertext dataset + training. 

- Model performance evaluation: Pending


TODO:
- Middleware library for easy use in solve.py script
- REEEEEEEEEEEEEEEEEE
"""

import re
import math
import string
import random
import pickle
import numpy as np
import pandas as pd
from collections import Counter
from math import gcd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, Input, BatchNormalization, Dropout, concatenate
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

import nltk
nltk.download('gutenberg')
nltk.download('wordnet2021')

from nltk.corpus import gutenberg, wordnet2021

# --------------------------
# Global Constants for Key Lengths
# --------------------------
MIN_KEY_LENGTH = 3
MAX_KEY_LENGTH = 50
NUM_CLASSES = MAX_KEY_LENGTH - MIN_KEY_LENGTH + 1  # For 3 to 50, that's 48 classes

# --------------------------
# Corpus loading with improved diversity
# --------------------------
def load_large_corpus() -> str:
    """
    Combine texts from Gutenberg and WordNet for improved diversity.
    For WordNet, we simply join the words (or definitions, if available) into a large string.
    """
    corpus_parts = []
    # Add Gutenberg texts
    for fid in gutenberg.fileids():
        text = gutenberg.raw(fid)
        corpus_parts.append(text)
    # Add WordNet words (if available)
    try:
        wordnet_words = " ".join(wordnet2021.words())
        corpus_parts.append(wordnet_words)
    except Exception as e:
        print("Warning: Could not load WordNet2021 words:", e)
    full_corpus = "\n".join(corpus_parts)
    # Clean: keep only letters (later uppercased)
    full_corpus = re.sub(r'[^A-Za-z]', ' ', full_corpus)
    return full_corpus

print("Loading large corpus from NLTK Gutenberg and WordNet...")
base_corpus = load_large_corpus()
print("Corpus length (characters):", len(base_corpus))


# Vigenère Encryption Helpers
def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using the Vigenère cipher with the given key.
    Only A–Z letters are considered (plaintext is cleaned and uppercased).
    """
    plaintext = re.sub(r'[^A-Z]', '', plaintext.upper())
    ciphertext = ""
    key_length = len(key)
    for i, char in enumerate(plaintext):
        p = ord(char) - ord('A')
        k = ord(key[i % key_length]) - ord('A')
        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))
    return ciphertext

def generate_random_key(length: int) -> str:
    """Generate a random uppercase key of the given length."""
    return ''.join(random.choices(string.ascii_uppercase, k=length))


# Feature Extraction Functions (77-dimensional vector)
def compute_index_of_coincidence(text: str) -> float:
    text = re.sub(r'[^A-Z]', '', text.upper())
    N = len(text)
    if N <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (N * (N - 1))

def friedman_key_length_estimate(text: str) -> float:
    text = re.sub(r'[^A-Z]', '', text.upper())
    N = len(text)
    if N == 0:
        return 0.0
    ic = compute_index_of_coincidence(text)
    try:
        return (0.028 * N) / (ic * (N - 1) - 0.038 * N + 0.066)
    except ZeroDivisionError:
        return 0.0

def compute_entropy(text: str) -> float:
    text = re.sub(r'[^A-Z]', '', text.upper())
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def compute_twist_index(text: str, m: int) -> float:
    text = re.sub(r'[^A-Z]', '', text.upper())
    if not text:
        return 0.0
    twist_total = 0.0
    for j in range(m):
        coset = text[j::m]
        if not coset:
            continue
        freq = Counter(coset)
        total = len(coset)
        freqs = [freq.get(letter, 0) / total for letter in string.ascii_uppercase]
        sorted_freqs = sorted(freqs, reverse=True)
        if len(sorted_freqs) < 26:
            sorted_freqs += [0.0] * (26 - len(sorted_freqs))
        twist_total += (sum(sorted_freqs[13:26]) - sum(sorted_freqs[0:13]))
    return (100 / m) * twist_total

def compute_twist_plus_index(text: str, m: int) -> float:
    if m <= 1:
        return 0.0
    t_m = compute_twist_index(text, m)
    twist_sum = sum(compute_twist_index(text, mu) for mu in range(1, m))
    return t_m - (1 / (m - 1)) * twist_sum

def compute_twist_pp_index(text: str, m: int) -> float:
    t_m = compute_twist_index(text, m)
    t_m_minus = compute_twist_index(text, m - 1) if m - 1 >= 1 else t_m
    t_m_plus = compute_twist_index(text, m + 1)
    return t_m - 0.5 * (t_m_minus + t_m_plus)

def compute_kasiski_features(text: str):
    text = re.sub(r'[^A-Z]', '', text.upper())
    trigram_positions = {}
    for i in range(len(text) - 2):
        trigram = text[i:i + 3]
        trigram_positions.setdefault(trigram, []).append(i)
    distances = []
    for positions in trigram_positions.values():
        if len(positions) > 1:
            for i in range(len(positions) - 1):
                distances.append(positions[i + 1] - positions[i])
    if distances:
        avg_distance = sum(distances) / len(distances)
        current_gcd = distances[0]
        for d in distances[1:]:
            current_gcd = gcd(current_gcd, d)
        gcd_distance = current_gcd
    else:
        avg_distance = 0.0
        gcd_distance = 0.0
    repeated_trigrams_count = sum(1 for positions in trigram_positions.values() if len(positions) > 1)
    return repeated_trigrams_count, avg_distance, gcd_distance

def compute_matthews_features(text: str):
    text = re.sub(r'[^A-Z]', '', text.upper())
    total = len(text)
    if total == 0:
        return 0.0, 0.0
    freq = Counter(text)
    percentages = [freq.get(letter, 0) / total for letter in string.ascii_uppercase]
    sorted_percents = sorted(percentages, reverse=True)
    H = sum(sorted_percents[:7])
    delta = H - sum(sorted_percents[-7:])
    return H, delta

def letter_frequency_features(text: str):
    text = re.sub(r'[^A-Z]', '', text.upper())
    total = len(text)
    cnt = Counter(text)
    return [cnt.get(letter, 0) / total if total > 0 else 0.0 for letter in string.ascii_uppercase]

def quotient_features(text: str):
    text = re.sub(r'[^A-Z]', '', text.upper())
    N = len(text)
    q = N // 12
    r = N % 12
    return [q, r]

def extract_features(text: str) -> np.ndarray:
    """
    Extract a 77-dimensional feature vector from ciphertext.
    Features include:
      1. Ciphertext length (1)
      2. Index of Coincidence (1)
      3. Friedman estimate (1)
      4. Entropy (1)
      5. Twist+ indices for m = 3 to 25 (23 features)
      6. Kasiski features (3 features)
      7. Matthews features (2 features)
      8. Quotient features (2 features)
      9. Letter frequency features (26 features)
      10. Twist++ indices for m = 3 to 19 (17 features)
    Total: 77 features.
    """
    features = []
    text_clean = re.sub(r'[^A-Z]', '', text.upper())
    features.append(len(text_clean))
    features.append(compute_index_of_coincidence(text))
    features.append(friedman_key_length_estimate(text))
    features.append(compute_entropy(text))
    for m in range(3, 26):
        features.append(compute_twist_plus_index(text, m))
    bk_count, bk_avg, bk_gcd = compute_kasiski_features(text)
    features.extend([bk_count, bk_avg, bk_gcd])
    matt_H, matt_delta = compute_matthews_features(text)
    features.extend([matt_H, matt_delta])
    features.extend(quotient_features(text))
    features.extend(letter_frequency_features(text))
    for m in range(3, 20):
        features.append(compute_twist_pp_index(text, m))
    if len(features) != 77:
        print("Warning: Feature vector length is", len(features))
    return np.array(features, dtype=np.float32)


# --------------------------
# Neural Network Model and Training (Hybrid Ensemble Model)
# --------------------------
def build_hybrid_ensemble_model(input_dim: int = 77, output_dim: int = NUM_CLASSES) -> tf.keras.Model:
    """
    Build a hybrid ensemble neural network that processes the engineered features
    via two separate branches. Their outputs are concatenated and passed through
    additional layers before making the final prediction.
    """
    inputs = Input(shape=(input_dim,))
    
    # Branch A: A deep tower with moderate dropout
    x1 = Dense(256, activation='relu')(inputs)
    x1 = BatchNormalization()(x1)
    x1 = Dropout(0.3)(x1)
    x1 = Dense(256, activation='relu')(x1)
    x1 = BatchNormalization()(x1)
    x1 = Dropout(0.3)(x1)
    x1 = Dense(128, activation='relu')(x1)
    x1 = BatchNormalization()(x1)
    x1 = Dropout(0.3)(x1)
    
    # Branch B: A wider tower with higher capacity and slightly higher dropout
    x2 = Dense(512, activation='relu')(inputs)
    x2 = BatchNormalization()(x2)
    x2 = Dropout(0.4)(x2)
    x2 = Dense(256, activation='relu')(x2)
    x2 = BatchNormalization()(x2)
    x2 = Dropout(0.4)(x2)
    x2 = Dense(128, activation='relu')(x2)
    x2 = BatchNormalization()(x2)
    x2 = Dropout(0.4)(x2)
    
    # Concatenate the outputs of the two branches
    combined = concatenate([x1, x2])
    x = Dense(256, activation='relu')(combined)
    x = BatchNormalization()(x)
    x = Dropout(0.3)(x)
    
    outputs = Dense(output_dim, activation='softmax')(x)
    
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def train_model_on_data(X_train, y_train, X_val, y_val, epochs: int = 50, batch_size: int = 128):
    model = build_hybrid_ensemble_model()
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size
    )
    return model, history


# --------------------------
# Synthetic Data Generation
# --------------------------
def generate_synthetic_data(plaintext: str, num_samples: int = 100000) -> pd.DataFrame:
    """
    Generate synthetic training samples.
    For each sample, a random segment (200–500 characters) is extracted from the corpus,
    a random key length (3–50) is chosen, a key is generated, the segment is encrypted,
    features are extracted, and the true key length is appended as the label.
    """
    data_rows = []
    corpus_length = len(plaintext)
    min_segment_length = 200
    max_segment_length = 500

    for i in range(num_samples):
        start = random.randint(0, max(0, corpus_length - max_segment_length - 1))
        segment_length = random.randint(min_segment_length, max_segment_length)
        segment = plaintext[start:start + segment_length]
        segment = re.sub(r'[^A-Za-z]', '', segment).upper()
        if len(segment) < min_segment_length:
            continue
        # Use key lengths between MIN_KEY_LENGTH and MAX_KEY_LENGTH (inclusive)
        key_length = random.randint(MIN_KEY_LENGTH, MAX_KEY_LENGTH)
        key = generate_random_key(key_length)
        ciphertext = vigenere_encrypt(segment, key)
        features = extract_features(ciphertext)
        # Append label (key length)
        row = features.tolist() + [key_length]
        data_rows.append(row)
        if (i + 1) % 1000 == 0:
            print(f"Generated {i + 1}/{num_samples} samples")
    df = pd.DataFrame(data_rows)
    return df


# --------------------------
# Predictor Wrapper (to be pickled)
# --------------------------
class KeyLengthPredictor:
    """
    A simple wrapper that encapsulates the feature extraction and ANN model.
    This object is later pickled so that it can be imported by a local library.
    """
    def __init__(self, model):
        self.model = model

    def extract_features(self, text: str) -> np.ndarray:
        return extract_features(text)

    def predict(self, text: str) -> int:
        features = self.extract_features(text).reshape(1, -1)
        prediction = self.model.predict(features)
        predicted_index = np.argmax(prediction)
        return predicted_index + MIN_KEY_LENGTH  # Adjust by the minimum key length


# --------------------------
# MAIN: Data Generation, Training, and Saving the Model/Wrapper
# --------------------------
def main():
    print("Loading large corpus from NLTK Gutenberg and WordNet...")
    base_corpus = load_large_corpus()
    print("Corpus length (characters):", len(base_corpus))
    
    print("\nGenerating synthetic training data (this may take a while)...")
    NUM_SAMPLES = 100000000  # Adjust as needed
    synthetic_df = generate_synthetic_data(base_corpus, num_samples=NUM_SAMPLES)
    
    csv_filename = "synthetic_vigenere_data.csv"
    synthetic_df.to_csv(csv_filename, index=False, header=False)
    print(f"\nSynthetic training data saved to '{csv_filename}'.")
    
    print("\nPreparing data for training...")
    # The last column is the label (key length); columns 0–76 are features.
    X = synthetic_df.iloc[:, :-1].values.astype(np.float32)
    y = synthetic_df.iloc[:, -1].values.astype(np.int32)
    # Convert key lengths (3–50) to categorical indices (0–47)
    y_cat = to_categorical(y - MIN_KEY_LENGTH, num_classes=NUM_CLASSES)
    
    X_train, X_val, y_train, y_val = train_test_split(X, y_cat, test_size=0.2, random_state=42)
    print("Training data shape:", X_train.shape)
    print("Validation data shape:", X_val.shape)
    
    NUM_EPOCHS = 100
    BATCH_SIZE = 256
    print(f"\nStarting model training for {NUM_EPOCHS} epochs with batch size {BATCH_SIZE}...")
    model, history = train_model_on_data(X_train, y_train, X_val, y_val,
                                         epochs=NUM_EPOCHS, batch_size=BATCH_SIZE)
    
    # Save the trained model in the new .keras format
    model.save("key_length_model.keras")
    print("\nModel saved in 'key_length_model.keras' format.")
    
    # Also create and pickle the predictor object
    predictor = KeyLengthPredictor(model)
    with open("key_length_model.pkl", "wb") as f:
        pickle.dump(predictor, f)
    print("KeyLengthPredictor object pickled as 'key_length_model.pkl'.")

if __name__ == "__main__":
    main()
