import os
import struct
import secrets
import base64
from io import BytesIO
from urllib.parse import quote_plus

from flask import (
    Flask, request, render_template, send_file,
    redirect, url_for, flash
)
from werkzeug.utils import secure_filename
from PIL import Image
import numpy as np

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------
# Config
# ---------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = secrets.token_hex(16)

ALLOWED_EXT = {'png'}
STATIC_STEGO_DIR = os.path.join(app.static_folder, "stego_storage")
os.makedirs(STATIC_STEGO_DIR, exist_ok=True)

# In-memory token store (simple). Structure: TOKENS[token] = {"path": path, "stego_id": id}
TOKENS = {}

# ---------------------------
# Crypto + Stego helpers
# ---------------------------
def allowed_filename(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(plain: bytes, password: str):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plain, None)
    return salt, nonce, ct

def decrypt_bytes(salt: bytes, nonce: bytes, ct: bytes, password: str):
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def pack_file_with_metadata(filename: str, mimetype: str, file_bytes: bytes) -> bytes:
    fname_b = filename.encode('utf-8')
    mime_b = (mimetype or "application/octet-stream").encode('utf-8')
    return struct.pack('>I', len(fname_b)) + fname_b + struct.pack('>I', len(mime_b)) + mime_b + file_bytes

def unpack_file_with_metadata(blob: bytes):
    off = 0
    fname_len = struct.unpack('>I', blob[off:off+4])[0]; off += 4
    fname = blob[off:off+fname_len].decode('utf-8'); off += fname_len
    mime_len = struct.unpack('>I', blob[off:off+4])[0]; off += 4
    mimetype = blob[off:off+mime_len].decode('utf-8'); off += mime_len
    file_bytes = blob[off:]
    return fname, mimetype, file_bytes

def bytes_to_bitarray(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def bitarray_to_bytes(bits: np.ndarray) -> bytes:
    pad_len = (-bits.size) % 8
    if pad_len:
        bits = np.concatenate([bits, np.zeros(pad_len, dtype=np.uint8)])
    return np.packbits(bits).tobytes()

def embed_bits_into_image(img: Image.Image, bits: np.ndarray) -> Image.Image:
    arr = np.array(img)
    flat = arr.flatten()
    if bits.size > flat.size:
        raise ValueError("Insufficient image capacity.")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return Image.fromarray(flat.reshape(arr.shape).astype(np.uint8))

def extract_bits_from_image(img: Image.Image, num_bits: int) -> np.ndarray:
    flat = np.array(img).flatten()
    return (flat[:num_bits] & 1).astype(np.uint8)

HEADER_BYTES = 16 + 12 + 4
HEADER_BITS = HEADER_BYTES * 8

# ---------------------------
# Routes
# ---------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    cover = request.files.get('cover_image')
    secret = request.files.get('secret_file')
    if not cover or not secret:
        flash("Both cover image (PNG) and secret file are required.", "error")
        return redirect(url_for('index'))
    if not allowed_filename(cover.filename):
        flash("Cover image must be PNG.", "error")
        return redirect(url_for('index'))

    secret_bytes = secret.read()
    orig_filename = secure_filename(secret.filename or "secret.bin")
    orig_mimetype = secret.mimetype or "application/octet-stream"
    plaintext = pack_file_with_metadata(orig_filename, orig_mimetype, secret_bytes)

    # generate token and encrypt with it
    token = secrets.token_urlsafe(8)
    salt, nonce, ciphertext = encrypt_bytes(plaintext, token)
    ct_len = len(ciphertext)
    header = salt + nonce + struct.pack('>I', ct_len)
    payload = header + ciphertext
    bits = bytes_to_bitarray(payload)

    cover_img = Image.open(cover.stream).convert('RGB')
    if bits.size > np.array(cover_img).size:
        flash("Cover image too small to hold the secret.", "error")
        return redirect(url_for('index'))

    stego_img = embed_bits_into_image(cover_img, bits)
    stego_id = secrets.token_urlsafe(8)
    stego_filename = f"{stego_id}.png"
    stego_path = os.path.join(STATIC_STEGO_DIR, stego_filename)
    stego_img.save(stego_path)

    # store token mapping
    TOKENS[token] = {"path": stego_path, "stego_id": stego_id}

    # public link to view the stego image
    share_link = url_for('view_stego', stego_id=stego_id, _external=True)

    # Construct whatsapp share URLs (two versions)
    # 1) link only
    wa_msg_link_only = quote_plus(f"Here is a secure stego image: {share_link}")
    whatsapp_link_only = f"https://wa.me/?text={wa_msg_link_only}"

    # 2) link + token (convenient but less secure)
    wa_msg_with_token = quote_plus(f"Stego link: {share_link}\nOne-time token: {token}\n(Use token to decrypt. Token is one-time use.)")
    whatsapp_link_with_token = f"https://wa.me/?text={wa_msg_with_token}"

    return render_template(
        'result.html',
        token=token,
        share_link=share_link,
        whatsapp_link_only=whatsapp_link_only,
        whatsapp_link_with_token=whatsapp_link_with_token,
        stego_filename=stego_filename
    )

@app.route('/stego/<stego_id>')
def view_stego(stego_id):
    stego_filename = f"{stego_id}.png"
    stego_path = os.path.join(STATIC_STEGO_DIR, stego_filename)
    if not os.path.exists(stego_path):
        flash("Stego image not found.", "error")
        return redirect(url_for('index'))
    # display using static file URL
    static_url = url_for('static', filename=f"stego_storage/{stego_filename}", _external=True)
    return render_template('stego_view.html', image_url=static_url, stego_id=stego_id)

@app.route('/decode/<stego_id>', methods=['POST'])
def decode(stego_id):
    token = request.form.get('token', '')
    stego_filename = f"{stego_id}.png"
    stego_path = os.path.join(STATIC_STEGO_DIR, stego_filename)
    if not os.path.exists(stego_path):
        flash("Stego image not found.", "error")
        return redirect(url_for('index'))

    if token not in TOKENS or TOKENS[token]["path"] != stego_path:
        flash("Invalid or already-used token.", "error")
        return redirect(url_for('view_stego', stego_id=stego_id))

    try:
        img = Image.open(stego_path).convert('RGB')
        arr = np.array(img)
        capacity = arr.size
        header_bits = extract_bits_from_image(img, HEADER_BITS)
        header = bitarray_to_bytes(header_bits)
        salt, nonce = header[:16], header[16:28]
        ct_len = struct.unpack('>I', header[28:32])[0]
        total_bits = HEADER_BITS + ct_len * 8
        if total_bits > capacity:
            flash("Image corrupted or incomplete payload.", "error")
            return redirect(url_for('view_stego', stego_id=stego_id))
        ct_bits = extract_bits_from_image(img, total_bits)[HEADER_BITS:]
        ct_bytes = bitarray_to_bytes(ct_bits)[:ct_len]

        plaintext = decrypt_bytes(salt, nonce, ct_bytes, token)
        fname, mimetype, file_bytes = unpack_file_with_metadata(plaintext)

        # invalidate token after successful use and optionally delete the stego image
        del TOKENS[token]
        # optionally remove file: uncomment the next line if you want to delete the stego image after decode
        # os.remove(stego_path)

        bio = BytesIO(file_bytes)
        bio.seek(0)
        return send_file(bio, as_attachment=True, download_name=fname, mimetype=mimetype)

    except Exception as e:
        flash("Decoding failed: " + str(e), "error")
        return redirect(url_for('view_stego', stego_id=stego_id))

# ---------------------------
# Run
# ---------------------------
if __name__ == '__main__':
    app.run(debug=True)