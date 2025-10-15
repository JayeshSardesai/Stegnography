from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS # Import CORS
import cv2
import numpy as np
import os
import struct
import io

# --- Flask App Setup ---
# Configure Flask to find files in the 'templates' and 'static' folders
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app) # Enable CORS to allow browser requests

# --- ChaCha20 Algorithm (from scratch) ---
# This part is unchanged
def u32(x): return x & 0xFFFFFFFF
def rotl(x, n): return u32((x << n) | (x >> (32 - n)))
def quarter_round(state, a, b, c, d):
    state[a] = u32(state[a] + state[b]); state[d] = rotl(state[d] ^ state[a], 16)
    state[c] = u32(state[c] + state[d]); state[b] = rotl(state[b] ^ state[c], 12)
    state[a] = u32(state[a] + state[b]); state[d] = rotl(state[d] ^ state[a], 8)
    state[c] = u32(state[c] + state[d]); state[b] = rotl(state[b] ^ state[c], 7)
def chacha20_block(key_words, nonce_words, counter):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    initial_state = constants + list(key_words) + [counter] + list(nonce_words)
    state = list(initial_state)
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12); quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14); quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15); quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13); quarter_round(state, 3, 4, 9, 14)
    for i in range(16):
        state[i] = u32(state[i] + initial_state[i])
    return struct.pack('<16I', *state)
def chacha20_encrypt_decrypt(message_bytes, key, nonce):
    key_words = struct.unpack('<8I', key)
    nonce_words = struct.unpack('<3I', nonce)
    keystream = b''
    counter = 1
    while len(keystream) < len(message_bytes):
        keystream += chacha20_block(key_words, nonce_words, counter)
        counter += 1
    trimmed_keystream = keystream[:len(message_bytes)]
    return bytes([a ^ b for a, b in zip(message_bytes, trimmed_keystream)])

# --- Flask Routes ---

# UPDATED: This route will now serve your main webpage
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    # This logic remains the same
    try:
        image_file = request.files['image']
        secret_text = request.form['message']
        key = request.form['key']

        key_bytes = key.encode('utf-8')
        normalized_key = (key_bytes * (32 // len(key_bytes) + 1))[:32]
        nonce = os.urandom(12)
        ciphertext = chacha20_encrypt_decrypt(secret_text.encode('utf-8'), normalized_key, nonce)
        data_to_embed = struct.pack('<I', len(ciphertext)) + nonce + ciphertext

        npimg = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        if img.shape[0] * img.shape[1] * 3 < len(data_to_embed) * 8:
            return jsonify({"error": "Image is too small for this message."}), 400

        data_index = 0
        bit_index = 0
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(3):
                    if data_index < len(data_to_embed):
                        bit = (data_to_embed[data_index] >> (7 - bit_index)) & 1
                        img[i, j, k] = (img[i, j, k] & 0xFE) | bit
                        bit_index += 1
                        if bit_index == 8:
                            bit_index = 0
                            data_index += 1
                    else: break
                else: continue
                break
            else: continue
            break
        
        is_success, buffer = cv2.imencode(".png", img)
        return send_file(io.BytesIO(buffer), mimetype='image/png', as_attachment=True, download_name='encrypted.png')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    # This logic remains the same
    try:
        image_file = request.files['image']
        key = request.form['key']
        normalized_key = (key.encode('utf-8') * (32 // len(key.encode('utf-8')) + 1))[:32]
        npimg = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        extracted_bits = []
        bits_to_extract = 32 
        bit_count = 0
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(3):
                    extracted_bits.append(img[i, j, k] & 1)
                    bit_count += 1
                    if bit_count >= bits_to_extract:
                        if bits_to_extract == 32:
                            len_bytes = bytes([int("".join(map(str, extracted_bits[i:i+8])), 2) for i in range(0, 32, 8)])
                            ciphertext_len = struct.unpack('<I', len_bytes)[0]
                            if ciphertext_len <= 0 or (4 + 12 + ciphertext_len) * 8 > len(img.flatten()):
                                return jsonify({"error": "Invalid message length found. Key may be wrong."}), 400
                            bits_to_extract = (4 + 12 + ciphertext_len) * 8
                        else:
                            break
                else: continue
                break
            else: continue
            break

        extracted_bytes = bytes([int("".join(map(str, extracted_bits[i:i+8])), 2) for i in range(0, len(extracted_bits), 8)])
        nonce = extracted_bytes[4:16]
        ciphertext = extracted_bytes[16:]
        decrypted_bytes = chacha20_encrypt_decrypt(ciphertext, normalized_key, nonce)
        return jsonify({"message": decrypted_bytes.decode('utf-8', errors='ignore')})
    except Exception:
        return jsonify({"error": "Decryption failed. Key may be wrong or image is corrupt."}), 400

if __name__ == '__main__':
    app.run(debug=True)