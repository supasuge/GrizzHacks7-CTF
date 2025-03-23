#!/usr/bin/env python3
import numpy as np
import wave
from array import array
from PIL import Image, ImageDraw, ImageFont
import argparse
import logging
import os
# Constants
BMP_IMAGE = "flag.bmp"
WAV_OUTPUT = "challenge.wav"
# check if these files exist in current directory, if so delete them.
if os.path.exists(BMP_IMAGE):
    os.remove(BMP_IMAGE)
if os.path.exists(WAV_OUTPUT):
    os.remove(WAV_OUTPUT)

SAMPLE_RATE = 44100  # Standard audio sample rate

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_flag_image(flag_text, width=800, height=200):
    """Create an 8-bit BMP image with the flag text for the spectrogram."""
    logger.info(f"Creating 8-bit BMP flag image: {BMP_IMAGE}...")

    img = Image.new("L", (width, height), "black")  # "L" mode ensures 8-bit grayscale
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 100)
    except IOError:
        font = ImageFont.load_default()
    draw.text((10, 40), flag_text, font=font, fill="white")

    img.save(BMP_IMAGE, format="BMP")
    logger.info(f"Flag image saved as {BMP_IMAGE}")

def make_wav(image_filename, output_wav=WAV_OUTPUT):
    """Convert an image into a `.wav` file with a recognizable spectrogram."""
    logger.info(f"Processing image: {image_filename} into spectrogram WAV...")

    # Load image as grayscale
    img = Image.open(image_filename).convert("L")
    img = np.array(img, dtype=np.float32).T[:, ::-1]  # Flip for correct orientation
    img = img ** 3  # Enhance contrast for clarity

    w, h = img.shape
    fft_size = h * 4
    data = np.fft.irfft(img, fft_size, axis=1).reshape((w * fft_size))
    data -= np.average(data)  # Remove DC bias
    data *= (2**15 - 1.0) / np.amax(data)  # Normalize amplitude
    audio_data = array("h", np.int_(data)).tobytes()

    # Save as WAV file
    with wave.open(output_wav, "w") as wavfile:
        wavfile.setparams((1, 2, SAMPLE_RATE, 0, "NONE", "not compressed"))
        wavfile.writeframes(audio_data)

    logger.info(f"Spectrogram audio saved: {output_wav}")

def main():
    flag = open('flag.txt').read().strip()
    create_flag_image(flag)
    # Step 2: Convert BMP image into a spectrogram WAV file
    make_wav(BMP_IMAGE)

if __name__ == "__main__":
    main()
