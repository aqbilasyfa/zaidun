import streamlit as st
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import time

# Fungsi Enkripsi dan Dekripsi
def encrypt_aes(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    return iv + cipher.encrypt(padded_data)

def decrypt_aes(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)

def encrypt_fernet(data, key):
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_fernet(ciphertext, key):
    f = Fernet(key)
    return f.decrypt(ciphertext)

def encrypt_blowfish(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_data = pad(data, Blowfish.block_size)
    return cipher.encrypt(padded_data)

def decrypt_blowfish(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), Blowfish.block_size)

# Fungsi Benchmark
def benchmark(algorithm, data, key):
    start_time = time.time()
    if algorithm == 'AES':
        encrypted_data = encrypt_aes(data, key)
        decrypted_data = decrypt_aes(encrypted_data, key)
    elif algorithm == 'Fernet':
        encrypted_data = encrypt_fernet(data, key)
        decrypted_data = decrypt_fernet(encrypted_data, key)
    elif algorithm == 'Blowfish':
        encrypted_data = encrypt_blowfish(data, key)
        decrypted_data = decrypt_blowfish(encrypted_data, key)
    else:
        raise ValueError("Algoritma tidak valid")
    end_time = time.time()
    return encrypted_data, decrypted_data, end_time - start_time

# Streamlit App
st.title("Benchmark Algoritma Enkripsi")

# Input Data
data_input = st.text_area("Masukkan data yang akan dienkripsi", value="Ini adalah data yang akan dienkripsi")
key_input = st.text_input("Masukkan kunci enkripsi (min. 16 karakter untuk AES)", value="kunci_rahasia")

# Pilihan Algoritma
algorithm = st.selectbox("Pilih Algoritma Enkripsi", ["AES", "Fernet", "Blowfish"])

# Tombol Eksekusi
if st.button("Jalankan Benchmark"):
    data = data_input.encode()
    key = key_input.encode()

    # Validasi Kunci
    if len(key) < 16:
        st.error("Kunci harus memiliki minimal 16 karakter.")
    else:
        # Untuk Fernet, kunci harus di-generate
        if algorithm == 'Fernet':
            key = Fernet.generate_key()

        try:
            encrypted_data, decrypted_data, time_taken = benchmark(algorithm, data, key)
            st.success(f"Waktu eksekusi {algorithm}: {time_taken:.6f} detik")
            st.text_area("Hasil Enkripsi (Base64)", value=encrypted_data.hex(), height=150)
            st.text_area("Hasil Dekripsi", value=decrypted_data.decode(), height=150)
        except Exception as e:
            st.error(f"Terjadi kesalahan: {str(e)}")
