import struct
from flask import Flask, render_template, request

app = Flask(__name__)

# Kunci statis default 128-bit untuk operasi sistem
SECRET_KEY = [0x01234567, 0x89ABCDEF, 0x11111111, 0x22222222]
DELTA = 0x9E3779B9

def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > 8 or padding_len < 1:
        raise ValueError("Struktur padding rusak atau format data salah.")
    return data[:-padding_len]

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
    sum_val = (DELTA * 32) & 0xFFFFFFFF
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

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        user_input = request.form.get('user_input', '').strip()
        operation_type = request.form.get('operation_type')
        
        if not user_input:
            result = {'error': 'Input teks tidak boleh kosong.'}
            return render_template('index.html', result=result)
            
        logs = []
        try:
            if operation_type == 'encrypt':
                plain_bytes = pad(user_input.encode('utf-8'))
                ciphertext = b''
                for idx, i in enumerate(range(0, len(plain_bytes), 8)):
                    block = plain_bytes[i:i+8]
                    
                    # 1. Ambil Nilai Register AWAL yang murni dari block data ini
                    v = struct.unpack('>LL', block) 
                    
                    # 2. Jalankan enkripsi (menghasilkan enc_v sebagai ciphertext, dan block_trace sebagai jalannya round)
                    enc_v, block_trace = encipher_block_trace(v, SECRET_KEY)
                    ciphertext += struct.pack('>LL', enc_v[0], enc_v[1])
                    
                    # 3. Catat ke log setelah kedua nilai di atas didapatkan dengan benar
                    logs.append({
                        'index': idx + 1, 
                        'raw': block.hex().upper(),
                        'init': [f"0x{v[0]:08X}", f"0x{v[1]:08X}"],       # Memakai 'v' asli
                        'rounds': block_trace,
                        'final': [f"0x{enc_v[0]:08X}", f"0x{enc_v[1]:08X}"] # Memakai 'enc_v' hasil akhir
                    })
                result = {'mode': 'Enkripsi', 'operation': 'encrypt', 'input': user_input, 'output': ciphertext.hex().upper(), 'logs': logs}
                            
            elif operation_type == 'decrypt':
                ciphertext_bytes = bytes.fromhex(user_input)
                plaintext = b''
                for idx, i in enumerate(range(0, len(ciphertext_bytes), 8)):
                    block = ciphertext_bytes[i:i+8]
                    
                    # 1. Ambil Nilai Register AWAL (masih berbentuk ciphertext hex)
                    v = struct.unpack('>LL', block)
                    
                    # 2. Jalankan dekripsi (menghasilkan dec_v sebagai plaintext asli)
                    dec_v, block_trace = decipher_block_trace(v, SECRET_KEY)
                    plaintext += struct.pack('>LL', dec_v[0], dec_v[1])
                    
                    # 3. Catat ke log
                    logs.append({
                        'index': idx + 1, 
                        'raw': block.hex().upper(),
                        'init': [f"0x{v[0]:08X}", f"0x{v[1]:08X}"],       # Memakai 'v' (Ciphertext awal blok)
                        'rounds': block_trace,
                        'final': [f"0x{dec_v[0]:08X}", f"0x{dec_v[1]:08X}"] # Memakai 'dec_v' (Plaintext akhir blok)
                    })
                decrypted_message = unpad(plaintext).decode('utf-8')
                result = {'mode': 'Dekripsi', 'operation': 'decrypt', 'input': user_input, 'output': decrypted_message, 'logs': logs}
                    
        except Exception as e:
            result = {'error': f"Gagal memproses data. Pastikan format input benar. (Error: {str(e)})"}
            
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)