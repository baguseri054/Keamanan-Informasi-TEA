from flask import Flask, render_template, request, send_file
import numpy as np
import cv2
import os

from skimage.metrics import structural_similarity as ssim
from skimage.metrics import peak_signal_noise_ratio as psnr

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

DELIMITER = "###EOF###"

# ==========================================
# VIGENERE
# ==========================================

def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    for i in range(len(plaintext)):
        char = plaintext[i]
        key_char = key[i % len(key)]
        ciphertext += chr((ord(char) + ord(key_char)) % 256)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        key_char = key[i % len(key)]
        plaintext += chr((ord(char) - ord(key_char)) % 256)
    return plaintext

# ==========================================
# CHAOS
# ==========================================

def generate_chaotic_indices(r, x0, total_pixels, required_length):
    if not (3.7 <= r <= 3.999):
        raise ValueError("FATAL: Parameter R harus berada di antara 3.7 hingga 3.999. Di luar rentang ini, rumus kehilangan sifat acaknya.")
    if x0 <= 0.0 or x0 >= 1.0 or x0 == 0.5:
        raise ValueError("FATAL: X0 harus di antara 0.01 hingga 0.99 dan tidak boleh persis 0.5")
        
    curr_x = x0
    for _ in range(1000):
        curr_x = r * curr_x * (1 - curr_x)
        
    chaos = np.zeros(total_pixels)
    chaos[0] = curr_x
    for i in range(1, total_pixels):
        chaos[i] = r * chaos[i-1] * (1 - chaos[i-1])

    indices = np.argsort(chaos)
    return indices[:required_length]

# ==========================================
# BINARY
# ==========================================

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)

# ==========================================
# EMBED
# ==========================================

def embed_message(img, message, key, r, x0):

    full_message = message + DELIMITER

    encrypted_msg = vigenere_encrypt(full_message, key)

    binary_msg = text_to_binary(encrypted_msg)

    total_pixels = img.size

    if len(binary_msg) > total_pixels:
        raise ValueError("Kapasitas gambar terlalu kecil")

    indices = generate_chaotic_indices(
        r,
        x0,
        total_pixels,
        len(binary_msg)
    )

    flat_img = img.flatten()

    for i in range(len(binary_msg)):
        idx = indices[i]
        flat_img[idx] = (flat_img[idx] & 254) | int(binary_msg[i])

    return flat_img.reshape(img.shape)

# ==========================================
# EXTRACT
# ==========================================

def extract_message(stego_img, key, r, x0):

    flat_img = stego_img.flatten()

    total_pixels = stego_img.size

    max_bits_to_extract = min(10000, total_pixels)

    indices = generate_chaotic_indices(
        r,
        x0,
        total_pixels,
        max_bits_to_extract
    )

    binary_msg = ""

    for idx in indices:

        binary_msg += str(flat_img[idx] & 1)

        if len(binary_msg) % 8 == 0:

            current_text = binary_to_text(binary_msg)

            decrypted_text = vigenere_decrypt(current_text, key)

            if decrypted_text.endswith(DELIMITER):
                return decrypted_text[:-len(DELIMITER)]

    return "Pesan tidak ditemukan"

# ==========================================
# ROUTES
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")

# ==========================================
# ENCRYPT
# ==========================================

@app.route("/", methods=["GET", "POST"])
def encrypt():

    if request.method == "POST":

        file = request.files["image"]

        message = request.form["message"]

        key = request.form["key"]

        r = float(request.form["r"])

        x0 = float(request.form["x0"])

        upload_path = os.path.join(
            UPLOAD_FOLDER,
            file.filename
        )

        file.save(upload_path)

        img = cv2.imread(upload_path)

        stego = embed_message(
            img,
            message,
            key,
            r,
            x0
        )

        output_path = os.path.join(
            OUTPUT_FOLDER,
            "stego.png"
        )

        cv2.imwrite(output_path, stego)

        nilai_psnr = psnr(img, stego)

        nilai_ssim = ssim(
            img,
            stego,
            channel_axis=2
        )

        return render_template(
            "index.html",
            success=True,
            psnr=round(nilai_psnr, 2),
            ssim=round(nilai_ssim, 5),
            image_path="stego.png"
        )

    return render_template("index.html")

# ==========================================
# DOWNLOAD
# ==========================================

@app.route("/download")
def download():
    return send_file(
        "outputs/stego.png",
        as_attachment=True
    )

# ==========================================
# DECRYPT
# ==========================================

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():

    if request.method == "POST":

        file = request.files["image"]

        key = request.form["key"]

        r = float(request.form["r"])

        x0 = float(request.form["x0"])

        upload_path = os.path.join(
            UPLOAD_FOLDER,
            file.filename
        )

        file.save(upload_path)

        img = cv2.imread(upload_path)

        result = extract_message(
            img,
            key,
            r,
            x0
        )

        return render_template(
            "decrypt.html",
            result=result
        )

    return render_template("decrypt.html")

if __name__ == "__main__":
    app.run(debug=True)