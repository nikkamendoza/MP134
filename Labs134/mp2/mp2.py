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
    public_key = private_key.public_key()
    return private_key, public_key

# Save key to a file
def save_key(key, filename, is_private=False):
    encoding = serialization.Encoding.PEM
    if is_private:
        pem_data = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem_data = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, "wb") as f:
        f.write(pem_data)

# Load key from a file
def load_key(filename, is_private=False):
    with open(filename, "rb") as f:
        key_data = f.read()
    if is_private:
        return serialization.load_pem_private_key(key_data, password=None)
    return serialization.load_pem_public_key(key_data)

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
        print(f"Encryption error: {e}")
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
        print(f"Decryption error: {e}")
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
        print(f"Signing error: {e}")
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
        print(f"Signature verification failed: {e}")
        return False

if __name__ == "__main__":
    # Generate key pairs if they do not exist
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
    
    # Read message from file
    with open("message.txt", "r") as f:
        message = f.read().strip()
    
    # Encrypt-Then-Sign
    encrypted_message = encrypt_message(message, enc_public)
    if encrypted_message:
        signature = sign_message(encrypted_message, sign_private)
        if signature:
            with open("ciphertext_and_signature.txt", "w") as f:
                f.write(f"Encrypted: {encrypted_message}\n")
                f.write(f"Signature: {signature}\n")
            
            print(f"Encrypted: {encrypted_message}")
            print(f"Signature: {signature}")
            
            # Verify-Then-Decrypt
            if verify_signature(encrypted_message, signature, sign_public):
                decrypted_message = decrypt_message(encrypted_message, enc_private)
                if decrypted_message:
                    with open("decrypted.txt", "w") as f:
                        f.write(decrypted_message)
                    print(f"Decrypted: {decrypted_message}")
                else:
                    print("Failed to decrypt message!")
            else:
                print("Signature verification failed!")
        else:
            print("Failed to sign message!")
    else:
        print("Failed to encrypt message!")
