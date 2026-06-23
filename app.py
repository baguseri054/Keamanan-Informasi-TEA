import struct
from flask import Flask, render_template, request

app = Flask(__name__)

DELTA = 0x9E3779B9

# ==========================================
# PADDING UTILITY (PKCS7)
# ==========================================
def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > 8 or padding_len < 1:
        raise ValueError("Padding hancur atau kunci verifikasi keliru.")
    return data[:-padding_len]

# ==========================================
# PARSE STRING KEY INTO 4 SUBKEYS (128-BIT)
# ==========================================
def parse_key_string(key_str: str) -> list:
    """Mengubah passphrase teks input dari web menjadi 4 blok subkey integer 32-bit."""
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes + b'\x00' * (16 - len(key_bytes))
    else:
        key_bytes = key_bytes[:16]
    return list(struct.unpack('>4L', key_bytes))

# ==========================================
# INTI OPERATIONS DENGAN TRACING STATUS
# ==========================================
def encipher_block_trace(v, k):
    v0, v1 = v[0], v[1]
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]
    sum_val = 0
    trace = []
    for r in range(32):
        sum_val = (sum_val + DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        trace.append({
            'round': r + 1,
            'sum': f"0x{sum_val:08X}",
            'v0': f"0x{v0:08X}",
            'v1': f"0x{v1:08X}"
        })
    return [v0, v1], trace

def decipher_block_trace(v, k):
    v0, v1 = v[0], v[1]
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]
    sum_val = 0xC6EF3720
    trace = []
    for r in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        trace.append({
            'round': 32 - r,
            'sum': f"0x{sum_val:08X}",
            'v0': f"0x{v0:08X}",
            'v1': f"0x{v1:08X}"
        })
        sum_val = (sum_val - DELTA) & 0xFFFFFFFF
    trace.reverse()
    return [v0, v1], trace

# ==========================================
# ROUTING FLASK HANDLERS
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        key_input = request.form.get('key', '').strip()
        try:
            if not message or not key_input:
                raise ValueError("Parameter data pesan teks dan kunci tidak boleh kosong.")
            
            secret_key = parse_key_string(key_input)
            data = pad(message.encode('utf-8'))
            ciphertext = b''
            logs = []
            
            for idx, i in enumerate(range(0, len(data), 8)):
                block = data[i:i+8]
                v = struct.unpack('>LL', block)
                enc_v, block_trace = encipher_block_trace(v, secret_key)
                ciphertext += struct.pack('>LL', enc_v[0], enc_v[1])
                logs.append({
                    'index': idx + 1,
                    'raw': block.hex().upper(),
                    'init': [f"0x{v[0]:08X}", f"0x{v[1]:08X}"],
                    'rounds': block_trace,
                    'final': [f"0x{enc_v[0]:08X}", f"0x{enc_v[1]:08X}"]
                })
            
            result = {
                'input': message,
                'output': ciphertext.hex().upper(),
                'logs': logs
            }
        except Exception as e:
            result = {'error': str(e)}
    return render_template('index.html', result=result)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    result = None
    if request.method == 'POST':
        ciphertext_hex = request.form.get('ciphertext', '').strip()
        key_input = request.form.get('key', '').strip()
        try:
            if not ciphertext_hex or not key_input:
                raise ValueError("Input ciphertext hexadecimal dan kunci tidak valid.")
            
            secret_key = parse_key_string(key_input)
            ciphertext_bytes = bytes.fromhex(ciphertext_hex)
            plaintext = b''
            logs = []
            
            for idx, i in enumerate(range(0, len(ciphertext_bytes), 8)):
                block = ciphertext_bytes[i:i+8]
                v = struct.unpack('>LL', block)
                dec_v, block_trace = decipher_block_trace(v, secret_key)
                plaintext += struct.pack('>LL', dec_v[0], dec_v[1])
                logs.append({
                    'index': idx + 1,
                    'raw': block.hex().upper(),
                    'init': [f"0x{v[0]:08X}", f"0x{v[1]:08X}"],
                    'rounds': block_trace,
                    'final': [f"0x{dec_v[0]:08X}", f"0x{dec_v[1]:08X}"]
                })
            
            decrypted_message = unpad(plaintext).decode('utf-8')
            result = {
                'input': ciphertext_hex,
                'output': decrypted_message,
                'logs': logs
            }
        except Exception as e:
            result = {'error': str(e)}
    return render_template('decrypt.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)