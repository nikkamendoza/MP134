RSA-OAEP Authenticated Encryption (Encrypt-Then-Sign)
🔐 Description
This program encrypts and decrypts short ASCII messages (≤140 characters) using RSA-OAEP and ensures authenticity using RSA-PSS signatures. It follows the encrypt-then-sign approach, generating and using separate RSA key pairs for encryption and signing.

All cryptographic operations are handled using the Python cryptography library.

📁 Files Included
mp2.py – Main Python script

message.txt – Input file containing the plaintext message

ciphertext_and_signature.txt – Output file containing the encrypted message and its signature

decrypted.txt – Decrypted output after verification

enc_private.pem, enc_public.pem – RSA keys for encryption/decryption

sign_private.pem, sign_public.pem – RSA keys for signing/verification

🚀 How It Works
Key Generation
The script automatically generates key pairs (enc_*.pem and sign_*.pem) if they don't already exist.

Encrypt-Then-Sign

Reads the message from message.txt.

Encrypts the message using RSA-OAEP with the encryption public key.

Signs the ciphertext using RSA-PSS with the signing private key.

Saves the ciphertext and signature to ciphertext_and_signature.txt.

Verify-Then-Decrypt

Verifies the signature using the signing public key.

If verification succeeds, decrypts the ciphertext using the encryption private key.

Saves the decrypted message to decrypted.txt.

🔧 How to Run
Step 1: Prepare Your Message
Write your message (max 140 ASCII characters) into message.txt.

Step 2: Run the Script
bash
Copy
Edit
python mp2.py
This performs encryption, signing, verification, and decryption in one go.

⚠️ Tampering Detection
If either the ciphertext or the signature in ciphertext_and_signature.txt is altered, the signature verification will fail, and decryption will be aborted. This confirms message integrity and authenticity.

📦 Dependencies
Python 3.6+

cryptography

Install via pip:

bash
Copy
Edit
pip install cryptography
🔐 Why Use Encrypt-Then-Sign?
Confidentiality: RSA-OAEP ensures only the intended recipient can decrypt the message.

Integrity & Authenticity: RSA-PSS digital signatures verify that the ciphertext hasn't been tampered with and confirm the sender's identity.

