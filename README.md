# 🔐 RSA-OAEP Authenticated Encryption — Encrypt-Then-Sign

A Python program that encrypts a short message using **RSA-OAEP** and authenticates it using **RSA-PSS** digital signatures.

✨ Uses the **Encrypt-Then-Sign** approach  
🔒 Ensures **confidentiality, authenticity, and integrity**  
✅ Built with the `cryptography` library — no custom crypto implementations

---

## 📂 Project Structure

. ├── mp2.py # Main program ├── message.txt # Input message (max 140 ASCII chars) ├── decrypted.txt # Output after successful decryption ├── ciphertext_and_signature.txt # Stores ciphertext and signature ├── enc_private.pem # Encryption private key ├── enc_public.pem # Encryption public key ├── sign_private.pem # Signing private key └── sign_public.pem # Signing public key


---

## 🚀 How It Works

1. **🔑 Key Generation**
   - Automatically creates RSA key pairs for encryption and signing (`2048-bit`) if they don’t already exist.

2. **🔐 Encrypt-Then-Sign**
   - Reads the message from `message.txt`
   - Encrypts using **RSA-OAEP** with SHA-256 and the **encryption public key**
   - Signs the ciphertext using **RSA-PSS** with SHA-256 and the **signing private key**
   - Saves to `ciphertext_and_signature.txt`

3. **🧾 Verify-Then-Decrypt**
   - Verifies signature using the **signing public key**
   - If valid, decrypts the message with the **encryption private key**
   - Writes decrypted message to `decrypted.txt`

---

## 💻 Usage

### 1. 🔧 Install Dependencies

```bash
pip install cryptography

2. ✏️ Prepare Message
Write your message (≤140 characters) into message.txt.

3. ▶️ Run the Program
bash
Copy
Edit
python mp2.py
