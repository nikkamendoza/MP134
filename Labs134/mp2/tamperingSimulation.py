from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import base64
import os

# Generate RSA key pairs (encryption and signing)
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()

# Save key to a file
def save_key(key, filename, is_private=False):
    pem_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ) if is_private else key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filename, "wb") as f:
        f.write(pem_data)

# Load key from a file
def load_key(filename, is_private=False):
    with open(filename, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None) if is_private else serialization.load_pem_public_key(key_data)

# Encrypt message using RSA-OAEP
def encrypt_message(message, public_key):
    try:
        ciphertext = public_key.encrypt(
            message.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        print(f"[Error] Encryption failed: {e}")
        return None

# Decrypt message using RSA-OAEP
def decrypt_message(ciphertext, private_key):
    try:
        ciphertext = base64.b64decode(ciphertext)
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception as e:
        print(f"[Error] Decryption failed: {e}")
        return None

# Sign the encrypted message
def sign_message(message, private_key):
    try:
        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    except Exception as e:
        print(f"[Error] Signing failed: {e}")
        return None

# Verify the signature
def verify_signature(message, signature, public_key):
    try:
        signature = base64.b64decode(signature)
        public_key.verify(
            signature,
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"[Error] Signature verification failed: {e}")
        return False

# Ensure key pairs exist or generate them if missing
def ensure_keys():
    if not os.path.exists("enc_private.pem") or not os.path.exists("enc_public.pem"):
        enc_private, enc_public = generate_keypair()
        save_key(enc_private, "enc_private.pem", is_private=True)
        save_key(enc_public, "enc_public.pem")
    else:
        enc_private = load_key("enc_private.pem", is_private=True)
        enc_public = load_key("enc_public.pem")

    if not os.path.exists("sign_private.pem") or not os.path.exists("sign_public.pem"):
        sign_private, sign_public = generate_keypair()
        save_key(sign_private, "sign_private.pem", is_private=True)
        save_key(sign_public, "sign_public.pem")
    else:
        sign_private = load_key("sign_private.pem", is_private=True)
        sign_public = load_key("sign_public.pem")

    return enc_private, enc_public, sign_private, sign_public

if __name__ == "__main__":
    enc_private, enc_public, sign_private, sign_public = ensure_keys()

    # Read message from file
    message_file = "message.txt"
    if not os.path.exists(message_file):
        print(f"[Error] {message_file} not found.")
        exit(1)

    with open(message_file, "r") as f:
        message = f.read().strip()

    # Encrypt-Then-Sign process
    encrypted_message = encrypt_message(message, enc_public)
    if encrypted_message:
        signature = sign_message(encrypted_message, sign_private)

        if signature:
            with open("ciphertext_and_signature.txt", "r") as f:
                lines = f.readlines()
                encrypted_message = lines[0].strip().split(": ")[1]
                signature = lines[1].strip().split(": ")[1]

            print("[TEST] Loaded previously saved encrypted message and signature.")

    # Verify-Then-Decrypt process

    # Simulate tampering by modifying the last character of the encrypted message
    tampered_encrypted_message = encrypted_message[:-1] + ("A" if encrypted_message[-1] != "A" else "B")

    print("\n[TEST] Tampering the encrypted message before verification...")
    if not verify_signature(encrypted_message, signature, sign_public):
        print("[Error] Signature verification failed. Aborting decryption.")
        exit(1)  # Stop execution if verification fails

    # Normal verification and decryption process
    if verify_signature(encrypted_message, signature, sign_public):
        decrypted_message = decrypt_message(encrypted_message, enc_private)

        if decrypted_message:
            with open("decrypted.txt", "w") as f:
                f.write(decrypted_message)
            print("[Success] Decryption and verification complete.")
            print("Decrypted message:", decrypted_message)
        else:
            print("[Error] Failed to decrypt message.")
    else:
        print("[Error] Signature verification failed.")

