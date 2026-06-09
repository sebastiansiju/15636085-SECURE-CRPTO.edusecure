"""
EduSecure - Cryptographic Security Platform (CLI Version)
==========================================================
A working command-line demonstration with:
- User Registration (bcrypt password hashing)
- User Login (password verification)
- Encrypt / Decrypt messages (AES-256-GCM)
- RSA Hybrid Encryption demo
- Digital Signatures (ECDSA P-256)
- HMAC Integrity Verification
- Secure Grade Management
- Audit Log with Hash Chain

Install required libraries:
    pip install cryptography bcrypt

Run:
    python edusecure_cli.py
"""

import os
import json
import hashlib
import hmac
import time
import getpass
from datetime import datetime

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# =============================================================================
# BACKEND CLASSES
# =============================================================================

class PasswordManager:
    """Manages password hashing and verification using bcrypt."""

    COST_FACTOR = 12

    def hash_password(self, plaintext_password):
        """Hash a password using bcrypt with automatic salt."""
        salt = bcrypt.gensalt(rounds=self.COST_FACTOR)
        hashed = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)
        return hashed

    def verify_password(self, plaintext_password, stored_hash):
        """Verify a password against stored bcrypt hash."""
        return bcrypt.checkpw(
            plaintext_password.encode('utf-8'), stored_hash
        )


class SymmetricEncryption:
    """AES-256-GCM authenticated encryption."""

    def generate_key(self):
        """Generate a random 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext, key, associated_data=None):
        """Encrypt data using AES-256-GCM."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext, key, associated_data=None):
        """Decrypt AES-256-GCM ciphertext."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)


class AsymmetricEncryption:
    """RSA-2048 asymmetric encryption."""

    def generate_keypair(self):
        """Generate an RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        return private_key, private_key.public_key()

    def encrypt(self, plaintext, public_key):
        """Encrypt with RSA-OAEP."""
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )

    def decrypt(self, ciphertext, private_key):
        """Decrypt RSA-OAEP ciphertext."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )


class DigitalSignature:
    """ECDSA digital signatures with P-256 curve."""

    def generate_keypair(self):
        """Generate an ECDSA key pair on P-256."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()

    def sign(self, data, private_key):
        """Sign data with ECDSA."""
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify(self, data, signature, public_key):
        """Verify an ECDSA signature."""
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


class IntegrityVerification:
    """HMAC-SHA256 message authentication."""

    def compute_hmac(self, message, key):
        """Compute HMAC-SHA256."""
        return hmac.new(key, message, hashlib.sha256).digest()

    def verify_hmac(self, message, key, expected_hmac):
        """Verify HMAC-SHA256 with constant-time comparison."""
        computed = hmac.new(key, message, hashlib.sha256).digest()
        return hmac.compare_digest(computed, expected_hmac)


class AuditLog:
    """Tamper-evident audit log using SHA-256 hash chain."""

    def __init__(self):
        self.entries = []
        self.previous_hash = hashlib.sha256(
            b"EDUSECURE_AUDIT_LOG_GENESIS"
        ).hexdigest()

    def add_entry(self, action, user, details):
        """Add a new entry to the audit log."""
        entry = {
            "index": len(self.entries),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "user": user,
            "details": details,
            "previous_hash": self.previous_hash
        }
        entry_string = json.dumps(entry, sort_keys=True).encode('utf-8')
        entry_hash = hashlib.sha256(entry_string).hexdigest()
        entry["hash"] = entry_hash
        self.entries.append(entry)
        self.previous_hash = entry_hash
        return entry

    def verify_chain(self):
        """Verify integrity of the entire audit log chain."""
        if not self.entries:
            return True, "Audit log is empty."
        genesis = hashlib.sha256(
            b"EDUSECURE_AUDIT_LOG_GENESIS"
        ).hexdigest()
        for i, entry in enumerate(self.entries):
            if i == 0:
                if entry["previous_hash"] != genesis:
                    return False, "Entry {}: Genesis mismatch.".format(i)
            else:
                if entry["previous_hash"] != self.entries[i - 1]["hash"]:
                    return False, "Entry {}: Chain broken.".format(i)
            stored_hash = entry["hash"]
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            entry_string = json.dumps(
                entry_copy, sort_keys=True
            ).encode('utf-8')
            if hashlib.sha256(entry_string).hexdigest() != stored_hash:
                return False, "Entry {}: Tampered!".format(i)
        return True, "All {} entries verified. Chain intact.".format(
            len(self.entries)
        )


class UserDatabase:
    """Simulated user database with bcrypt hashed passwords."""

    def __init__(self):
        self.users = {}
        self.pm = PasswordManager()
        self.ds = DigitalSignature()

    def register(self, username, password, role, full_name):
        """Register a new user."""
        if username in self.users:
            return False, "Username '{}' already exists!".format(username)
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if len(password) < 6:
            return False, "Password must be at least 6 characters."

        start = time.time()
        hashed = self.pm.hash_password(password)
        elapsed = time.time() - start

        sign_private, sign_public = self.ds.generate_keypair()

        self.users[username] = {
            "password_hash": hashed,
            "role": role,
            "full_name": full_name,
            "sign_private": sign_private,
            "sign_public": sign_public,
            "registered": datetime.utcnow().isoformat() + "Z"
        }
        return True, "User '{}' registered! (hashed in {:.3f}s)".format(
            username, elapsed
        )

    def login(self, username, password):
        """Authenticate a user."""
        if username not in self.users:
            return False, "Invalid username or password."
        stored_hash = self.users[username]["password_hash"]
        start = time.time()
        valid = self.pm.verify_password(password, stored_hash)
        elapsed = time.time() - start
        if valid:
            return True, "Login successful! Welcome, {} (verified in {:.3f}s)".format(
                self.users[username]["full_name"], elapsed
            )
        return False, "Invalid username or password."

    def get_user(self, username):
        """Get user data."""
        return self.users.get(username, None)


# =============================================================================
# CLI APPLICATION
# =============================================================================

class EduSecureCLI:
    """Main EduSecure command-line application."""

    def __init__(self):
        # Initialize all crypto components
        self.db = UserDatabase()
        self.se = SymmetricEncryption()
        self.ae = AsymmetricEncryption()
        self.ds = DigitalSignature()
        self.iv = IntegrityVerification()
        self.audit = AuditLog()
        self.aes_key = self.se.generate_key()
        self.hmac_key = os.urandom(32)
        self.current_user = None
        self.encrypted_grades = {}
        self.last_encrypted = None
        self.last_signature = None
        self.last_signed_data = None
        self.last_hmac = None
        self.last_hmac_message = None

        # Create default test accounts
        self.db.register("seb", "password123", "Student", "sebastian siju")
        self.db.register("keir", "teaching456", "Lecturer", "keir starmer")
        self.db.register("carol", "admin789", "Admin", "Carol johns")
        self.audit.add_entry("SYSTEM", "system", "EduSecure platform started")

    # =========================================================================
    # DISPLAY HELPERS
    # =========================================================================

    def print_header(self, title):
        """Print a section header."""
        print("\n" + "=" * 60)
        print("  " + title)
        print("=" * 60)

    def print_line(self):
        """Print a separator line."""
        print("-" * 60)

    def print_menu(self, title, options):
        """Print a numbered menu."""
        self.print_header(title)
        for num, text in options:
            print("  [{}] {}".format(num, text))
        self.print_line()

    def get_input(self, prompt):
        """Get user input with a prompt."""
        return input("  > " + prompt + ": ").strip()

    def get_password(self, prompt):
        """Get password input (hidden)."""
        try:
            return getpass.getpass("  > " + prompt + ": ")
        except Exception:
            # Fallback if getpass doesn't work (some IDEs)
            return input("  > " + prompt + " (visible): ").strip()

    def pause(self):
        """Pause and wait for user to press Enter."""
        input("\n  Press Enter to continue...")

    # =========================================================================
    # LOGIN / REGISTRATION SCREEN
    # =========================================================================

    def login_screen(self):
        """Show login and registration screen."""
        while True:
            self.print_menu("EDUSECURE - Cryptographic Security Platform", [
                ("1", "Login"),
                ("2", "Register New Account"),
                ("3", "View Default Test Accounts"),
                ("0", "Exit")
            ])

            choice = self.get_input("Choose option")

            if choice == "1":
                self.handle_login()
                if self.current_user:
                    return True

            elif choice == "2":
                self.handle_register()

            elif choice == "3":
                self.show_test_accounts()

            elif choice == "0":
                print("\n  Goodbye!")
                return False

            else:
                print("\n  Invalid option. Try again.")

    def show_test_accounts(self):
        """Display default test accounts."""
        self.print_header("DEFAULT TEST ACCOUNTS")
        print("  Username     Password        Role")
        self.print_line()
        print("  seb        password123     Student")
        print("  keir          teaching456     Lecturer")
        print("  carol        admin789        Admin")
        self.print_line()
        print("  Use these to test the login system.")
        self.pause()

    def handle_login(self):
        """Process login attempt."""
        self.print_header("LOGIN")

        username = self.get_input("Username")
        password = self.get_password("Password")

        if not username or not password:
            print("\n  ERROR: Please enter both username and password.")
            return

        success, message = self.db.login(username, password)

        if success:
            self.current_user = username
            self.audit.add_entry("LOGIN", username, "Successful login")
            print("\n  " + message)
        else:
            self.audit.add_entry(
                "LOGIN_FAILED", username, "Failed login attempt"
            )
            print("\n  ERROR: " + message)

    def handle_register(self):
        """Process new user registration."""
        self.print_header("REGISTER NEW ACCOUNT")

        full_name = self.get_input("Full Name")
        username = self.get_input("Username (min 3 chars)")
        password = self.get_password("Password (min 6 chars)")

        print("\n  Select Role:")
        print("  [1] Student")
        print("  [2] Lecturer")
        print("  [3] Admin")
        role_choice = self.get_input("Role (1/2/3)")

        role_map = {"1": "Student", "2": "Lecturer", "3": "Admin"}
        role = role_map.get(role_choice, "Student")

        if not full_name or not username or not password:
            print("\n  ERROR: All fields are required.")
            return

        success, message = self.db.register(
            username, password, role, full_name
        )

        if success:
            self.audit.add_entry(
                "REGISTRATION", username,
                "New {} account created".format(role)
            )
            user_data = self.db.get_user(username)
            hash_str = user_data["password_hash"].decode('utf-8')

            print("\n  " + message)
            print("\n  Account Details:")
            print("  Username:  " + username)
            print("  Full Name: " + full_name)
            print("  Role:      " + role)
            print("\n  Password Hash (bcrypt):")
            print("  " + hash_str)
            print("\n  Your password is NEVER stored in plaintext.")
            print("  The hash includes: algorithm + cost factor + salt + hash")
        else:
            print("\n  ERROR: " + message)

        self.pause()

    # =========================================================================
    # MAIN DASHBOARD
    # =========================================================================

    def dashboard(self):
        """Show the main dashboard after login."""
        while True:
            user_data = self.db.get_user(self.current_user)

            self.print_menu(
                "DASHBOARD - {} ({})".format(
                    user_data["full_name"], user_data["role"]
                ),
                [
                    ("1", "AES-256-GCM Encryption Demo"),
                    ("2", "RSA Hybrid Encryption Demo"),
                    ("3", "Digital Signature Demo"),
                    ("4", "HMAC Integrity Demo"),
                    ("5", "Secure Grade Management"),
                    ("6", "View Audit Log"),
                    ("7", "Verify Audit Log Chain"),
                    ("8", "View Registered Users"),
                    ("9", "Secure File Transmission Demo"),
                    ("0", "Logout")
                ]
            )

            choice = self.get_input("Choose option")

            if choice == "1":
                self.encryption_menu()
            elif choice == "2":
                self.rsa_demo()
            elif choice == "3":
                self.signature_menu()
            elif choice == "4":
                self.hmac_menu()
            elif choice == "5":
                self.grades_menu()
            elif choice == "6":
                self.view_audit_log()
            elif choice == "7":
                self.verify_audit_chain()
            elif choice == "8":
                self.view_users()
            elif choice == "9":
                self.secure_transmission_demo()
            elif choice == "0":
                self.audit.add_entry(
                    "LOGOUT", self.current_user, "User logged out"
                )
                self.current_user = None
                print("\n  Logged out successfully.")
                return
            else:
                print("\n  Invalid option.")

    # =========================================================================
    # OPTION 1: AES-256-GCM ENCRYPTION
    # =========================================================================

    def encryption_menu(self):
        """AES-256-GCM encryption demonstration."""
        while True:
            self.print_menu("AES-256-GCM ENCRYPTION", [
                ("1", "Encrypt a message"),
                ("2", "Decrypt last message"),
                ("3", "Tamper detection test"),
                ("0", "Back to dashboard")
            ])

            choice = self.get_input("Choose option")

            if choice == "1":
                self.do_encrypt()
            elif choice == "2":
                self.do_decrypt()
            elif choice == "3":
                self.do_tamper_test()
            elif choice == "0":
                return
            else:
                print("\n  Invalid option.")

    def do_encrypt(self):
        """Encrypt a message with AES-256-GCM."""
        self.print_header("AES-256-GCM ENCRYPTION")

        message = self.get_input("Enter message to encrypt")
        if not message:
            print("\n  ERROR: Enter a message.")
            return

        start = time.time()
        nonce, ciphertext = self.se.encrypt(
            message.encode('utf-8'), self.aes_key
        )
        elapsed = time.time() - start

        self.last_encrypted = (nonce, ciphertext, message)

        print("\n  ENCRYPTION RESULT:")
        self.print_line()
        print("  Plaintext:    " + message)
        print("  AES Key:      " + self.aes_key.hex()[:32] + "...")
        print("  Nonce (96b):  " + nonce.hex())
        print("  Ciphertext:   " + ciphertext.hex()[:48] + "...")
        print("  CT Length:    {} bytes (includes 16-byte auth tag)".format(
            len(ciphertext)
        ))
        print("  Time:         {:.4f}s".format(elapsed))
        self.print_line()
        print("  Data is now ENCRYPTED and AUTHENTICATED.")

        self.audit.add_entry(
            "ENCRYPT", self.current_user,
            "Encrypted {} bytes with AES-256-GCM".format(len(message))
        )
        self.pause()

    def do_decrypt(self):
        """Decrypt the last encrypted message."""
        self.print_header("AES-256-GCM DECRYPTION")

        if not self.last_encrypted:
            print("\n  ERROR: No encrypted message found. Encrypt one first.")
            self.pause()
            return

        nonce, ciphertext, original = self.last_encrypted

        start = time.time()
        decrypted = self.se.decrypt(nonce, ciphertext, self.aes_key)
        elapsed = time.time() - start

        print("\n  DECRYPTION RESULT:")
        self.print_line()
        print("  Ciphertext:   " + ciphertext.hex()[:48] + "...")
        print("  Decrypted:    " + decrypted.decode('utf-8'))
        print("  Matches:      " + str(decrypted.decode('utf-8') == original))
        print("  Auth Tag:     VERIFIED (integrity intact)")
        print("  Time:         {:.4f}s".format(elapsed))
        self.print_line()

        self.audit.add_entry(
            "DECRYPT", self.current_user, "Decrypted AES-256-GCM data"
        )
        self.pause()

    def do_tamper_test(self):
        """Test AES-GCM tamper detection."""
        self.print_header("AES-GCM TAMPER DETECTION TEST")

        if not self.last_encrypted:
            print("\n  ERROR: No encrypted message. Encrypt one first.")
            self.pause()
            return

        nonce, ciphertext, original = self.last_encrypted

        # Verify original works
        decrypted = self.se.decrypt(nonce, ciphertext, self.aes_key)
        print("\n  Original decryption: SUCCESS")
        print("  Decrypted: " + decrypted.decode('utf-8'))

        # Tamper with ciphertext
        print("\n  Tampering with ciphertext (flipping bits)...")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        try:
            self.se.decrypt(nonce, tampered, self.aes_key)
            print("  WARNING: Tampered data accepted! (should not happen)")
        except Exception as e:
            print("  Tampered ciphertext: REJECTED!")
            print("  Exception: " + type(e).__name__)
            print("  GCM authentication tag FAILED as expected.")

        # Tamper with nonce
        print("\n  Tampering with nonce...")
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0xFF
        tampered_nonce = bytes(tampered_nonce)

        try:
            self.se.decrypt(tampered_nonce, ciphertext, self.aes_key)
            print("  WARNING: Wrong nonce accepted!")
        except Exception:
            print("  Wrong nonce: REJECTED!")

        self.print_line()
        print("  CONCLUSION: AES-256-GCM detects ANY modification")
        print("  to the ciphertext, nonce, or associated data.")

        self.audit.add_entry(
            "TAMPER_TEST", self.current_user, "AES-GCM tamper test performed"
        )
        self.pause()

    # =========================================================================
    # OPTION 2: RSA HYBRID ENCRYPTION
    # =========================================================================

    def rsa_demo(self):
        """RSA-2048 hybrid encryption demonstration."""
        self.print_header("RSA-2048 HYBRID ENCRYPTION DEMO")

        print("\n  Generating RSA-2048 key pair...")
        start = time.time()
        priv, pub = self.ae.generate_keypair()
        elapsed = time.time() - start
        print("  Key generation: {:.3f}s".format(elapsed))
        print("  Key size: {} bits".format(priv.key_size))

        # Show public key
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("\n  Public Key (PEM):")
        for line in pub_bytes.decode('utf-8').strip().split('\n')[:3]:
            print("  " + line)
        print("  ...")

        # Generate session key
        session_key = os.urandom(32)
        print("\n  AES Session Key: " + session_key.hex())

        # Encrypt session key with RSA
        print("\n  Encrypting session key with RSA-OAEP...")
        start = time.time()
        enc_key = self.ae.encrypt(session_key, pub)
        elapsed = time.time() - start
        print("  Encrypted key: " + enc_key.hex()[:48] + "...")
        print("  Encrypted key length: {} bytes".format(len(enc_key)))
        print("  Encryption time: {:.4f}s".format(elapsed))

        # Decrypt session key
        print("\n  Decrypting session key with private key...")
        start = time.time()
        dec_key = self.ae.decrypt(enc_key, priv)
        elapsed = time.time() - start
        print("  Recovered key: " + dec_key.hex())
        print("  Keys match: " + str(session_key == dec_key))
        print("  Decryption time: {:.4f}s".format(elapsed))

        # Use session key for AES
        message = "Confidential student records for Alice Johnson"
        print("\n  Using session key for AES-256-GCM:")
        nonce, ct = self.se.encrypt(message.encode('utf-8'), session_key)
        pt = self.se.decrypt(nonce, ct, session_key)
        print("  Original:  " + message)
        print("  Encrypted: " + ct.hex()[:48] + "...")
        print("  Decrypted: " + pt.decode('utf-8'))

        self.print_line()
        print("  HYBRID ENCRYPTION:")
        print("  1. RSA encrypts the AES key (small, secure)")
        print("  2. AES encrypts the actual data (fast, any size)")
        print("  3. Best of both: RSA security + AES speed")

        self.audit.add_entry(
            "RSA_DEMO", self.current_user, "RSA hybrid encryption demo"
        )
        self.pause()

    # =========================================================================
    # OPTION 3: DIGITAL SIGNATURES
    # =========================================================================

    def signature_menu(self):
        """Digital signature demonstration menu."""
        while True:
            self.print_menu("ECDSA DIGITAL SIGNATURES (P-256)", [
                ("1", "Sign a document"),
                ("2", "Verify signature"),
                ("3", "Tamper detection test"),
                ("0", "Back to dashboard")
            ])

            choice = self.get_input("Choose option")

            if choice == "1":
                self.do_sign()
            elif choice == "2":
                self.do_verify_sig()
            elif choice == "3":
                self.do_sig_tamper()
            elif choice == "0":
                return
            else:
                print("\n  Invalid option.")

    def do_sign(self):
        """Sign a document with ECDSA."""
        self.print_header("ECDSA DIGITAL SIGNATURE")

        document = self.get_input("Enter document text to sign")
        if not document:
            document = "Assignment: Cryptography Report by {} - {}".format(
                self.current_user,
                datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            )
            print("  Using default: " + document)

        user_data = self.db.get_user(self.current_user)
        data_bytes = document.encode('utf-8')

        start = time.time()
        signature = self.ds.sign(data_bytes, user_data["sign_private"])
        elapsed = time.time() - start

        doc_hash = hashlib.sha256(data_bytes).hexdigest()

        self.last_signature = signature
        self.last_signed_data = data_bytes

        print("\n  SIGNATURE RESULT:")
        self.print_line()
        print("  Signer:     {} ({})".format(
            user_data["full_name"], self.current_user
        ))
        print("  Algorithm:  ECDSA P-256 + SHA-256")
        print("  Document:   " + document[:60] + ("..." if len(document) > 60 else ""))
        print("  SHA-256:    " + doc_hash)
        print("  Signature:  " + signature.hex()[:48] + "...")
        print("  Sig Length: {} bytes".format(len(signature)))
        print("  Sign Time:  {:.4f}s".format(elapsed))
        self.print_line()
        print("  Document is now SIGNED.")
        print("  Non-repudiation: Signer cannot deny authorship.")

        self.audit.add_entry(
            "SIGN", self.current_user,
            "Signed document ({} bytes)".format(len(data_bytes))
        )
        self.pause()

    def do_verify_sig(self):
        """Verify a digital signature."""
        self.print_header("SIGNATURE VERIFICATION")

        if not self.last_signature:
            print("\n  ERROR: No signed document. Sign one first.")
            self.pause()
            return

        user_data = self.db.get_user(self.current_user)

        start = time.time()
        is_valid = self.ds.verify(
            self.last_signed_data, self.last_signature,
            user_data["sign_public"]
        )
        elapsed = time.time() - start

        print("\n  VERIFICATION RESULT:")
        self.print_line()
        print("  Document:   " + self.last_signed_data.decode('utf-8')[:60])
        print("  Verifier:   {}'s public key".format(self.current_user))
        print("  Valid:      " + str(is_valid))
        print("  Time:       {:.4f}s".format(elapsed))
        self.print_line()

        if is_valid:
            print("  RESULT: SIGNATURE VERIFIED")
            print("  - Document has NOT been modified")
            print("  - Signer identity CONFIRMED")
            print("  - Non-repudiation GUARANTEED")
        else:
            print("  RESULT: SIGNATURE INVALID")
            print("  - Document may have been TAMPERED with")

        self.audit.add_entry(
            "VERIFY_SIG", self.current_user,
            "Signature verification: {}".format(
                "VALID" if is_valid else "INVALID"
            )
        )
        self.pause()

    def do_sig_tamper(self):
        """Test tamper detection with digital signatures."""
        self.print_header("SIGNATURE TAMPER DETECTION")

        if not self.last_signature:
            print("\n  ERROR: No signed document. Sign one first.")
            self.pause()
            return

        user_data = self.db.get_user(self.current_user)

        # Verify original
        original_valid = self.ds.verify(
            self.last_signed_data, self.last_signature,
            user_data["sign_public"]
        )

        # Tamper with document
        tampered = self.last_signed_data + b" [TAMPERED BY ATTACKER]"
        tampered_valid = self.ds.verify(
            tampered, self.last_signature, user_data["sign_public"]
        )

        # Wrong key test
        fake_priv, fake_pub = self.ds.generate_keypair()
        wrong_key_valid = self.ds.verify(
            self.last_signed_data, self.last_signature, fake_pub
        )

        print("\n  TAMPER DETECTION RESULTS:")
        self.print_line()
        print("  Original document:    VALID = " + str(original_valid))
        print("  Tampered document:    VALID = " + str(tampered_valid))
        print("  Wrong public key:     VALID = " + str(wrong_key_valid))
        self.print_line()
        print("\n  Original:  " + self.last_signed_data.decode('utf-8')[:60])
        print("  Tampered:  " + tampered.decode('utf-8')[:60])
        self.print_line()
        print("  CONCLUSION:")
        print("  - ANY modification to the document invalidates the signature")
        print("  - Only the correct public key can verify the signature")
        print("  - Provides integrity + authentication + non-repudiation")

        self.audit.add_entry(
            "TAMPER_TEST", self.current_user, "Signature tamper test"
        )
        self.pause()

    # =========================================================================
    # OPTION 4: HMAC INTEGRITY
    # =========================================================================

    def hmac_menu(self):
        """HMAC demonstration menu."""
        while True:
            self.print_menu("HMAC-SHA256 INTEGRITY VERIFICATION", [
                ("1", "Compute HMAC for a message"),
                ("2", "Verify HMAC"),
                ("3", "Tamper detection test"),
                ("0", "Back to dashboard")
            ])

            choice = self.get_input("Choose option")

            if choice == "1":
                self.do_hmac()
            elif choice == "2":
                self.do_verify_hmac()
            elif choice == "3":
                self.do_hmac_tamper()
            elif choice == "0":
                return
            else:
                print("\n  Invalid option.")

    def do_hmac(self):
        """Compute HMAC-SHA256."""
        self.print_header("HMAC-SHA256 COMPUTATION")

        message = self.get_input("Enter message")
        if not message:
            message = "grade_update:STU-2024-001:7065CEM:A+:92"
            print("  Using default: " + message)

        msg_bytes = message.encode('utf-8')
        mac = self.iv.compute_hmac(msg_bytes, self.hmac_key)
        self.last_hmac = mac
        self.last_hmac_message = msg_bytes

        print("\n  HMAC RESULT:")
        self.print_line()
        print("  Message:    " + message)
        print("  HMAC Key:   " + self.hmac_key.hex()[:32] + "...")
        print("  HMAC Tag:   " + mac.hex())
        print("  Tag Length:  {} bytes (256 bits)".format(len(mac)))
        self.print_line()
        print("  This tag authenticates:")
        print("  1. The message has not been modified (integrity)")
        print("  2. It was created by someone with the key (authentication)")

        self.audit.add_entry(
            "HMAC_COMPUTE", self.current_user, "Computed HMAC-SHA256"
        )
        self.pause()

    def do_verify_hmac(self):
        """Verify HMAC-SHA256."""
        self.print_header("HMAC-SHA256 VERIFICATION")

        if not self.last_hmac:
            print("\n  ERROR: No HMAC computed. Compute one first.")
            self.pause()
            return

        is_valid = self.iv.verify_hmac(
            self.last_hmac_message, self.hmac_key, self.last_hmac
        )

        print("\n  VERIFICATION RESULT:")
        self.print_line()
        print("  Message:  " + self.last_hmac_message.decode('utf-8'))
        print("  HMAC:     " + self.last_hmac.hex())
        print("  Valid:    " + str(is_valid))
        self.print_line()
        print("  Uses constant-time comparison (prevents timing attacks)")

        if is_valid:
            print("  Message AUTHENTICATED. Integrity confirmed.")

        self.audit.add_entry(
            "HMAC_VERIFY", self.current_user, "HMAC verification performed"
        )
        self.pause()

    def do_hmac_tamper(self):
        """Test HMAC tamper detection."""
        self.print_header("HMAC TAMPER DETECTION TEST")

        if not self.last_hmac:
            print("\n  ERROR: No HMAC computed. Compute one first.")
            self.pause()
            return

        original_valid = self.iv.verify_hmac(
            self.last_hmac_message, self.hmac_key, self.last_hmac
        )

        tampered = self.last_hmac_message + b" [TAMPERED]"
        tampered_valid = self.iv.verify_hmac(
            tampered, self.hmac_key, self.last_hmac
        )

        wrong_key = os.urandom(32)
        wrong_key_valid = self.iv.verify_hmac(
            self.last_hmac_message, wrong_key, self.last_hmac
        )

        print("\n  RESULTS:")
        self.print_line()
        print("  Original message:  VALID = " + str(original_valid))
        print("  Tampered message:  VALID = " + str(tampered_valid))
        print("  Wrong key:         VALID = " + str(wrong_key_valid))
        self.print_line()
        print("  CONCLUSION:")
        print("  - Tampered message REJECTED")
        print("  - Wrong key REJECTED")
        print("  - Only correct message + correct key = VALID")

        self.audit.add_entry(
            "HMAC_TAMPER", self.current_user, "HMAC tamper test"
        )
        self.pause()

    # =========================================================================
    # OPTION 5: GRADE MANAGEMENT
    # =========================================================================

    def grades_menu(self):
        """Grade management menu."""
        while True:
            self.print_menu("SECURE GRADE MANAGEMENT", [
                ("1", "Add encrypted & signed grade"),
                ("2", "View all grades (decrypt & verify)"),
                ("3", "Tamper test on grade"),
                ("0", "Back to dashboard")
            ])

            choice = self.get_input("Choose option")

            if choice == "1":
                self.add_grade()
            elif choice == "2":
                self.view_grades()
            elif choice == "3":
                self.tamper_grade_test()
            elif choice == "0":
                return
            else:
                print("\n  Invalid option.")

    def add_grade(self):
        """Add an encrypted and signed grade entry."""
        self.print_header("ADD ENCRYPTED & SIGNED GRADE")

        student_id = self.get_input("Student ID (e.g. STU-2024-001)")
        if not student_id:
            student_id = "STU-2024-001"

        course = self.get_input("Course code (e.g. 7065CEM)")
        if not course:
            course = "7065CEM"

        print("\n  Grade options: A+, A, B+, B, C+, C, D, F")
        grade = self.get_input("Grade")
        if not grade:
            grade = "A+"

        user_data = self.db.get_user(self.current_user)

        # Create grade record
        grade_record = json.dumps({
            "student_id": student_id,
            "course": course,
            "grade": grade,
            "lecturer": self.current_user,
            "full_name": user_data["full_name"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }).encode('utf-8')

        # Sign grade
        signature = self.ds.sign(grade_record, user_data["sign_private"])

        # Encrypt grade
        nonce, ciphertext = self.se.encrypt(grade_record, self.aes_key)

        # Store
        key = "{}_{}".format(student_id, course)
        self.encrypted_grades[key] = {
            "nonce": nonce,
            "ciphertext": ciphertext,
            "signature": signature,
            "signed_by": self.current_user,
            "original_data": grade_record  # kept for tamper demo
        }

        print("\n  GRADE STORED SECURELY:")
        self.print_line()
        print("  Student:     " + student_id)
        print("  Course:      " + course)
        print("  Grade:       " + grade)
        print("  Signed by:   " + user_data["full_name"])
        print("  Encrypted:   " + ciphertext.hex()[:48] + "...")
        print("  Signature:   " + signature.hex()[:48] + "...")
        self.print_line()
        print("  Grade is:")
        print("  - ENCRYPTED (AES-256-GCM) -> confidentiality")
        print("  - SIGNED (ECDSA P-256) -> integrity + non-repudiation")

        self.audit.add_entry(
            "GRADE_ENTRY", self.current_user,
            "Added grade {} for {} in {}".format(grade, student_id, course)
        )
        self.pause()

    def view_grades(self):
        """View all grades (decrypted and verified)."""
        self.print_header("ALL GRADES (DECRYPTED & VERIFIED)")

        if not self.encrypted_grades:
            print("\n  No grades stored yet.")
            print("  Add a grade first (option 1).")
            self.pause()
            return

        for key, data in self.encrypted_grades.items():
            # Decrypt
            decrypted = self.se.decrypt(
                data["nonce"], data["ciphertext"], self.aes_key
            )
            grade_record = json.loads(decrypted.decode('utf-8'))

            # Verify signature
            signer = self.db.get_user(data["signed_by"])
            sig_valid = self.ds.verify(
                decrypted, data["signature"], signer["sign_public"]
            )

            self.print_line()
            print("  Student:    " + grade_record["student_id"])
            print("  Course:     " + grade_record["course"])
            print("  Grade:      " + grade_record["grade"])
            print("  Lecturer:   " + grade_record.get("full_name", "N/A"))
            print("  Timestamp:  " + grade_record["timestamp"])
            print("  Signed by:  " + data["signed_by"])
            print("  Signature:  " + ("VALID" if sig_valid else "INVALID"))

        self.print_line()
        print("  Total grades: " + str(len(self.encrypted_grades)))

        self.audit.add_entry(
            "GRADE_VIEW", self.current_user,
            "Viewed {} grades".format(len(self.encrypted_grades))
        )
        self.pause()

    def tamper_grade_test(self):
        """Demonstrate grade tamper detection."""
        self.print_header("GRADE TAMPER DETECTION TEST")

        if not self.encrypted_grades:
            print("\n  No grades stored. Add one first.")
            self.pause()
            return

        # Get first grade
        key = list(self.encrypted_grades.keys())[0]
        data = self.encrypted_grades[key]

        # Decrypt original
        decrypted = self.se.decrypt(
            data["nonce"], data["ciphertext"], self.aes_key
        )
        signer = self.db.get_user(data["signed_by"])

        # Verify original
        original_valid = self.ds.verify(
            decrypted, data["signature"], signer["sign_public"]
        )

        # Tamper with the grade
        grade_dict = json.loads(decrypted.decode('utf-8'))
        original_grade = grade_dict["grade"]
        grade_dict["grade"] = "F"  # Change grade to F
        tampered_data = json.dumps(grade_dict).encode('utf-8')

        tampered_valid = self.ds.verify(
            tampered_data, data["signature"], signer["sign_public"]
        )

        print("\n  TESTING GRADE TAMPERING:")
        self.print_line()
        print("  Student: " + grade_dict["student_id"])
        print("  Course:  " + grade_dict["course"])
        print()
        print("  Original grade:  {} -> Signature VALID = {}".format(
            original_grade, original_valid
        ))
        print("  Tampered grade:  F  -> Signature VALID = {}".format(
            tampered_valid
        ))
        self.print_line()

        if not tampered_valid:
            print("  TAMPERING DETECTED!")
            print("  Changing the grade from {} to F".format(original_grade))
            print("  INVALIDATED the digital signature.")
            print("  The system would REJECT this modification.")
        else:
            print("  WARNING: Tamper not detected (unexpected).")

        self.audit.add_entry(
            "GRADE_TAMPER_TEST", self.current_user,
            "Grade tamper detection test on " + key
        )
        self.pause()

    # =========================================================================
    # OPTION 6: VIEW AUDIT LOG
    # =========================================================================

    def view_audit_log(self):
        """Display the complete audit log."""
        self.print_header("AUDIT LOG (Hash-Chain)")

        if not self.audit.entries:
            print("\n  Audit log is empty.")
            self.pause()
            return

        for entry in self.audit.entries:
            print("  #{:<3} [{}] {}".format(
                entry["index"], entry["action"], entry["user"]
            ))
            print("       Detail: " + entry["details"])
            print("       Time:   " + entry["timestamp"])
            print("       Hash:   " + entry["hash"][:40] + "...")
            print("       Prev:   " + entry["previous_hash"][:40] + "...")
            print()

        self.print_line()
        print("  Total entries: " + str(len(self.audit.entries)))
        print("  Each entry is chained to the previous via SHA-256 hash.")
        self.pause()

    # =========================================================================
    # OPTION 7: VERIFY AUDIT CHAIN
    # =========================================================================

    def verify_audit_chain(self):
        """Verify the audit log hash chain."""
        self.print_header("AUDIT LOG CHAIN VERIFICATION")

        print("\n  Verifying hash chain integrity...")

        is_valid, message = self.audit.verify_chain()

        print("  Result: " + message)
        print("  Chain valid: " + str(is_valid))

        if is_valid:
            print("\n  All entries are intact.")
            print("  No tampering detected.")

            # Demonstrate tamper detection
            print("\n  --- SIMULATING TAMPERING ---")
            if len(self.audit.entries) > 1:
                original = self.audit.entries[1]["details"]
                self.audit.entries[1]["details"] = "HACKED ENTRY"

                is_valid2, message2 = self.audit.verify_chain()
                print("  After tampering entry #1:")
                print("  Result: " + message2)
                print("  Chain valid: " + str(is_valid2))

                if not is_valid2:
                    print("  TAMPERING DETECTED by hash-chain verification!")

                # Restore
                self.audit.entries[1]["details"] = original
                print("\n  (Entry restored to original)")
            else:
                print("  (Need more entries to demonstrate)")

        self.audit.add_entry(
            "AUDIT_VERIFY", self.current_user, "Audit chain verification"
        )
        self.pause()

    # =========================================================================
    # OPTION 8: VIEW USERS
    # =========================================================================

    def view_users(self):
        """Display all registered users."""
        self.print_header("REGISTERED USERS")

        for username, data in self.db.users.items():
            self.print_line()
            print("  Username:    " + username)
            print("  Full Name:   " + data["full_name"])
            print("  Role:        " + data["role"])
            print("  Registered:  " + data["registered"])
            print("  Password:    " + data["password_hash"].decode('utf-8'))
            print("  (bcrypt hash - password is NOT stored in plaintext)")

        self.print_line()
        print("  Total users: " + str(len(self.db.users)))
        self.pause()

    # =========================================================================
    # OPTION 9: SECURE FILE TRANSMISSION
    # =========================================================================

    def secure_transmission_demo(self):
        """Full secure file transmission simulation."""
        self.print_header("SECURE FILE TRANSMISSION SIMULATION")
        print("  Combines: AES-256-GCM + ECDSA + SHA-256 + HMAC")
        print("  Simulates: Student submitting assignment securely")

        user_data = self.db.get_user(self.current_user)

        # Step 1: Prepare file
        file_content = (
            "EduSecure Assignment Submission\n"
            "================================\n"
            "Student: {} ({})\n"
            "Module: 7065CEM Cryptography\n"
            "Date: {}\n\n"
            "Content: This report analyses the cryptographic controls "
            "required to secure an online education platform. "
            "It covers AES-256-GCM for encryption, ECDSA for digital "
            "signatures, bcrypt for password hashing, and HMAC-SHA256 "
            "for message authentication..."
        ).format(
            user_data["full_name"], self.current_user,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        ).encode('utf-8')

        print("\n  [STEP 1] Student prepares assignment")
        print("  File size: {} bytes".format(len(file_content)))

        # Step 2: Hash
        print("\n  [STEP 2] Compute file integrity hash (SHA-256)")
        file_hash = hashlib.sha256(file_content).hexdigest()
        print("  SHA-256: " + file_hash)

        # Step 3: Sign
        print("\n  [STEP 3] Student signs the file (ECDSA P-256)")
        start = time.time()
        signature = self.ds.sign(file_content, user_data["sign_private"])
        elapsed = time.time() - start
        print("  Signature: " + signature.hex()[:48] + "...")
        print("  Sign time: {:.4f}s".format(elapsed))

        # Step 4: Encrypt
        print("\n  [STEP 4] Encrypt file (AES-256-GCM)")
        metadata = "submission:{}:7065CEM".format(
            self.current_user
        ).encode('utf-8')
        nonce, encrypted_file = self.se.encrypt(
            file_content, self.aes_key, metadata
        )
        print("  Encrypted size: {} bytes".format(len(encrypted_file)))
        print("  Nonce: " + nonce.hex())

        # Step 5: HMAC
        print("\n  [STEP 5] Compute HMAC over transmission package")
        package = nonce + encrypted_file + signature
        package_hmac = self.iv.compute_hmac(package, self.hmac_key)
        print("  Package HMAC: " + package_hmac.hex())

        # Transmission
        print("\n  " + "=" * 50)
        print("  >>> TRANSMITTING OVER SECURE CHANNEL (TLS 1.3) >>>")
        print("  " + "=" * 50)

        # Step 6: Verify HMAC
        print("\n  [STEP 6] Server verifies package HMAC")
        hmac_valid = self.iv.verify_hmac(package, self.hmac_key, package_hmac)
        print("  HMAC verification: " + ("PASS" if hmac_valid else "FAIL"))

        # Step 7: Decrypt
        print("\n  [STEP 7] Server decrypts file (AES-256-GCM)")
        decrypted_file = self.se.decrypt(
            nonce, encrypted_file, self.aes_key, metadata
        )
        content_match = decrypted_file == file_content
        print("  Decrypted size: {} bytes".format(len(decrypted_file)))
        print("  Content matches: " + str(content_match))

        # Step 8: Verify hash
        print("\n  [STEP 8] Server verifies file hash (SHA-256)")
        received_hash = hashlib.sha256(decrypted_file).hexdigest()
        hash_valid = received_hash == file_hash
        print("  Expected: " + file_hash[:40] + "...")
        print("  Received: " + received_hash[:40] + "...")
        print("  Hash match: " + ("PASS" if hash_valid else "FAIL"))

        # Step 9: Verify signature
        print("\n  [STEP 9] Server verifies digital signature (ECDSA)")
        sig_valid = self.ds.verify(
            decrypted_file, signature, user_data["sign_public"]
        )
        print("  Signature: " + ("PASS" if sig_valid else "FAIL"))
        print("  Non-repudiation: Author confirmed")

        # Summary
        all_passed = all([hmac_valid, content_match, hash_valid, sig_valid])
        print("\n  " + "=" * 50)
        print("  SECURE TRANSMISSION SUMMARY")
        print("  " + "=" * 50)
        print("  HMAC Integrity:     " + ("PASS" if hmac_valid else "FAIL"))
        print("  AES-GCM Decryption: " + ("PASS" if content_match else "FAIL"))
        print("  SHA-256 Hash Match: " + ("PASS" if hash_valid else "FAIL"))
        print("  ECDSA Signature:    " + ("PASS" if sig_valid else "FAIL"))
        print("  " + "-" * 50)
        print("  Overall: " + ("ALL CHECKS PASSED" if all_passed else "FAILED"))

        self.audit.add_entry(
            "SECURE_TRANSMISSION", self.current_user,
            "Secure file transmission demo - {}".format(
                "ALL PASSED" if all_passed else "FAILED"
            )
        )
        self.pause()

    # =========================================================================
    # RUN APPLICATION
    # =========================================================================

    def run(self):
        """Start the EduSecure application."""
        print("\n" + "=" * 60)
        print("  EDUSECURE - Cryptographic Security Platform")
        print("  Command Line Interface")
        print("=" * 60)
        print("  Algorithms: bcrypt, AES-256-GCM, RSA-2048, ECDSA P-256,")
        print("              SHA-256, HMAC-SHA256")
        print("=" * 60)

        while True:
            if not self.current_user:
                should_continue = self.login_screen()
                if not should_continue:
                    break
            else:
                self.dashboard()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    app = EduSecureCLI()
    app.run()