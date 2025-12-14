"""
A Cryptography Algorithm Implementation GUI to exercise the library.

Features:
- Generate RSA key pair
- AES key generate, encrypt/decrypt (GCM)
- RSA encrypt/decrypt
- Hash file
- Text encryption tab with password list support

Note: This file expects `customtkinter` installed.
Run from project root: python -m gui.app

"""
import os
import sys
import customtkinter as ctk
from tkinter import filedialog, messagebox
import base64

# Fix import path - add parent directory to sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from crypto_algos.aes import AESCipher
from crypto_algos.rsa import RSAKeyPair
from crypto_algos.hash import compute_hash

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class CryptoGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Crypto GUI — AES / RSA / Hash")
        self.geometry("900x600")
        self.minsize(800, 500)
        
        # Internal state
        self.aes_key: bytes | None = None
        self.rsa_pair: RSAKeyPair | None = None
        
        self._build_ui()

    def _build_ui(self):
        # Create tabview
        self.tabview = ctk.CTkTabview(self, width=880, height=560)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add tabs
        self.tabview.add("File Operations")
        self.tabview.add("Text Encryption")
        
        # Build each tab
        self._build_file_operations_tab()
        self._build_text_encryption_tab()
        
        # Status bar at bottom
        self.status_label = ctk.CTkLabel(
            self, 
            text="Ready | No keys loaded",
            anchor="w",
            font=("", 10)
        )
        self.status_label.pack(side="bottom", fill="x", padx=12, pady=(0, 6))
        
        self.update_status()

    def _build_file_operations_tab(self):
        """Build the original file operations tab"""
        tab = self.tabview.tab("File Operations")
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        # Left controls
        frame_controls = ctk.CTkScrollableFrame(tab, width=220)
        frame_controls.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        # RSA section
        ctk.CTkLabel(frame_controls, text="🔐 RSA Operations", font=("", 14, "bold")).pack(padx=8, pady=(6, 0))
        
        ctk.CTkLabel(frame_controls, text="Key Size (bits):").pack(padx=8, pady=(8, 0))
        self.rsa_bits = ctk.CTkOptionMenu(
            frame_controls, 
            values=["1024", "2048", "3072", "4096"], 
            dynamic_resizing=False
        )
        self.rsa_bits.set("2048")
        self.rsa_bits.pack(padx=8, pady=4)
        
        ctk.CTkButton(frame_controls, text="Generate RSA Keys", command=self.on_gen_rsa).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="Load Private Key", command=self.on_load_priv).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="Load Public Key", command=self.on_load_pub).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="RSA Encrypt File", command=self.on_rsa_encrypt).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="RSA Decrypt File", command=self.on_rsa_decrypt).pack(padx=8, pady=4)

        # Separator
        ctk.CTkFrame(frame_controls, height=2, fg_color="gray").pack(fill="x", padx=8, pady=12)

        # AES section
        ctk.CTkLabel(frame_controls, text="🔒 AES Operations", font=("", 14, "bold")).pack(padx=8, pady=(6, 0))
        
        ctk.CTkButton(frame_controls, text="Generate AES Key", command=self.on_gen_aes).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="Load AES Key", command=self.on_load_aes).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="AES Encrypt (GCM)", command=self.on_aes_encrypt).pack(padx=8, pady=4)
        ctk.CTkButton(frame_controls, text="AES Decrypt (GCM)", command=self.on_aes_decrypt).pack(padx=8, pady=4)

        # Separator
        ctk.CTkFrame(frame_controls, height=2, fg_color="gray").pack(fill="x", padx=8, pady=12)

        # Hash section
        ctk.CTkLabel(frame_controls, text="# Hash Operations", font=("", 14, "bold")).pack(padx=8, pady=(6, 0))
        
        ctk.CTkLabel(frame_controls, text="Algorithm:").pack(padx=8, pady=(8, 0))
        self.hash_alg = ctk.CTkOptionMenu(
            frame_controls, 
            values=["sha256", "sha512", "sha1", "md5"],
            dynamic_resizing=False
        )
        self.hash_alg.set("sha256")
        self.hash_alg.pack(padx=8, pady=4)
        
        ctk.CTkButton(frame_controls, text="Compute Hash", command=self.on_hash).pack(padx=8, pady=4)

        # Separator
        ctk.CTkFrame(frame_controls, height=2, fg_color="gray").pack(fill="x", padx=8, pady=12)

        # Clear button
        ctk.CTkButton(
            frame_controls, 
            text="Clear Log", 
            command=self.clear_log,
            fg_color="gray",
            hover_color="darkgray"
        ).pack(padx=8, pady=4)

        # Right: big text area for logs/output
        frame_right = ctk.CTkFrame(tab)
        frame_right.grid(row=0, column=1, padx=(0, 12), pady=12, sticky="nsew")
        frame_right.grid_columnconfigure(0, weight=1)
        frame_right.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(frame_right, text="📋 Operation Log", font=("", 14, "bold")).grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="w"
        )

        self.txt = ctk.CTkTextbox(frame_right, width=520, height=480, font=("Courier", 11))
        self.txt.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")
        
        self.log("=== Crypto GUI Started ===")
        self.log(f"Project root: {ROOT}")

    def _build_text_encryption_tab(self):
        """Build the text encryption tab"""
        tab = self.tabview.tab("Text Encryption")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        # Top controls frame
        controls_frame = ctk.CTkFrame(tab)
        controls_frame.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        controls_frame.grid_columnconfigure(1, weight=1)

        # Encryption type selector
        ctk.CTkLabel(controls_frame, text="🔐 Encryption Type:", font=("", 12, "bold")).grid(
            row=0, column=0, padx=8, pady=8, sticky="w"
        )
        
        self.encryption_type = ctk.CTkSegmentedButton(
            controls_frame,
            values=["AES", "RSA"],
            command=self.on_encryption_type_changed
        )
        self.encryption_type.set("AES")
        self.encryption_type.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        # AES Key management
        ctk.CTkLabel(controls_frame, text="🔑 AES Key:", font=("", 12, "bold")).grid(
            row=1, column=0, padx=8, pady=8, sticky="w"
        )
        
        aes_key_buttons_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        aes_key_buttons_frame.grid(row=1, column=1, padx=8, pady=8, sticky="w")
        
        ctk.CTkButton(
            aes_key_buttons_frame, 
            text="Generate Key", 
            command=self.on_gen_aes,
            width=120
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            aes_key_buttons_frame, 
            text="Load Key", 
            command=self.on_load_aes,
            width=120
        ).pack(side="left", padx=4)

        # RSA Key management
        ctk.CTkLabel(controls_frame, text="🔐 RSA Keys:", font=("", 12, "bold")).grid(
            row=2, column=0, padx=8, pady=8, sticky="w"
        )
        
        rsa_key_buttons_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        rsa_key_buttons_frame.grid(row=2, column=1, padx=8, pady=8, sticky="w")
        
        ctk.CTkButton(
            rsa_key_buttons_frame, 
            text="Generate Keys", 
            command=self.on_gen_rsa,
            width=120
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            rsa_key_buttons_frame, 
            text="Load Private", 
            command=self.on_load_priv,
            width=120
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            rsa_key_buttons_frame, 
            text="Load Public", 
            command=self.on_load_pub,
            width=120
        ).pack(side="left", padx=4)

        # Plaintext input section
        input_frame = ctk.CTkFrame(tab)
        input_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_frame, text="📝 Plaintext Input:", font=("", 12, "bold")).grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="w"
        )

        self.plaintext_input = ctk.CTkTextbox(input_frame, height=100, font=("Courier", 11))
        self.plaintext_input.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="ew")

        # Single text encryption buttons
        single_buttons_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        single_buttons_frame.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="w")

        ctk.CTkButton(
            single_buttons_frame,
            text="🔒 Encrypt Text",
            command=self.on_encrypt_text,
            width=140,
            fg_color="#1f6aa5"
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            single_buttons_frame,
            text="🔓 Decrypt Text",
            command=self.on_decrypt_text,
            width=140,
            fg_color="#1f6aa5"
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            single_buttons_frame,
            text="Clear",
            command=self.clear_text_fields,
            width=100,
            fg_color="gray",
            hover_color="darkgray"
        ).pack(side="left", padx=4)

        # Output section
        output_frame = ctk.CTkFrame(tab)
        output_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        output_frame.grid_columnconfigure(0, weight=1)
        output_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(output_frame, text="🔐 Ciphertext Output:", font=("", 12, "bold")).grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="w"
        )

        self.ciphertext_output = ctk.CTkTextbox(output_frame, height=100, font=("Courier", 11))
        self.ciphertext_output.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")

        # Password list section
        password_frame = ctk.CTkFrame(tab)
        password_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))
        password_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(password_frame, text="📋 Password List Processing:", font=("", 12, "bold")).grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="w"
        )

        password_buttons_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        password_buttons_frame.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="w")

        ctk.CTkButton(
            password_buttons_frame,
            text="📂 Load Password List",
            command=self.on_load_password_list,
            width=160
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            password_buttons_frame,
            text="🔒 Encrypt List",
            command=self.on_encrypt_password_list,
            width=140
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            password_buttons_frame,
            text="💾 Download Encrypted List",
            command=self.on_download_encrypted_list,
            width=180
        ).pack(side="left", padx=4)

        # Store encrypted password list
        self.encrypted_password_list = []

    # ---------- helpers ----------
    def log(self, *parts):
        text = " ".join(str(p) for p in parts) + "\n"
        self.txt.insert("end", text)
        self.txt.see("end")

    def clear_log(self):
        self.txt.delete("1.0", "end")
        self.log("=== Log Cleared ===")

    def update_status(self):
        aes_status = "✓ AES" if self.aes_key else "✗ AES"
        rsa_status = "✓ RSA" if self.rsa_pair else "✗ RSA"
        self.status_label.configure(text=f"Status: {aes_status} | {rsa_status}")

    def clear_text_fields(self):
        self.plaintext_input.delete("1.0", "end")
        self.ciphertext_output.delete("1.0", "end")

    # ---------- RSA actions ----------
    def on_gen_rsa(self):
        try:
            bits = int(self.rsa_bits.get())
            self.log(f"Generating RSA {bits}-bit key pair... (this may take a moment)")
            self.update()
            
            self.rsa_pair = RSAKeyPair.generate(bits=bits)
            
            # Save to files
            with open("rsa_priv.pem", "wb") as f:
                f.write(self.rsa_pair.export_private())
            with open("rsa_pub.pem", "wb") as f:
                f.write(self.rsa_pair.export_public())
            
            self.log(f"✓ Generated RSA {bits}-bit keys")
            self.log(f"  → Saved: rsa_priv.pem / rsa_pub.pem")
            self.update_status()
            messagebox.showinfo("Success", f"RSA {bits}-bit keys generated successfully!")
        except Exception as e:
            self.log(f"✗ Error generating RSA keys: {e}")
            messagebox.showerror("Error", f"Failed to generate RSA keys:\n{e}")

    def on_load_priv(self):
        try:
            path = filedialog.askopenfilename(
                title="Select RSA private PEM", 
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not path:
                return
            
            with open(path, "rb") as f:
                pem = f.read()
            
            self.rsa_pair = RSAKeyPair.from_private_pem(pem)
            self.log(f"✓ Loaded private key: {os.path.basename(path)}")
            self.update_status()
        except Exception as e:
            self.log(f"✗ Error loading private key: {e}")
            messagebox.showerror("Error", f"Failed to load private key:\n{e}")

    def on_load_pub(self):
        try:
            path = filedialog.askopenfilename(
                title="Select RSA public PEM", 
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not path:
                return
            
            with open(path, "rb") as f:
                pem = f.read()
            
            self.rsa_pair = RSAKeyPair.from_public_pem(pem)
            self.log(f"✓ Loaded public key: {os.path.basename(path)}")
            self.update_status()
        except Exception as e:
            self.log(f"✗ Error loading public key: {e}")
            messagebox.showerror("Error", f"Failed to load public key:\n{e}")

    def on_rsa_encrypt(self):
        if not self.rsa_pair:
            messagebox.showwarning("No RSA Key", "Please generate or load an RSA key first")
            return
        
        try:
            path = filedialog.askopenfilename(title="Select file to RSA encrypt")
            if not path:
                return
            
            with open(path, "rb") as f:
                data = f.read()
            
            # Note: RSA can only encrypt small amounts of data
            if len(data) > 190:  # Conservative limit for 2048-bit key
                messagebox.showwarning(
                    "File Too Large", 
                    "RSA can only encrypt small files (<190 bytes).\nFor larger files, use AES encryption."
                )
                return
            
            encrypted = self.rsa_pair.encrypt(data)
            out = path + ".rsa"
            
            with open(out, "wb") as f:
                f.write(encrypted)
            
            self.log(f"✓ RSA encrypted: {os.path.basename(path)} → {os.path.basename(out)}")
            self.log(f"  Size: {len(data)} bytes → {len(encrypted)} bytes")
        except Exception as e:
            self.log(f"✗ RSA encryption failed: {e}")
            messagebox.showerror("Error", f"RSA encryption failed:\n{e}")

    def on_rsa_decrypt(self):
        if not self.rsa_pair:
            messagebox.showwarning("No RSA Key", "Please load a private key first")
            return
        
        try:
            path = filedialog.askopenfilename(title="Select .rsa file to decrypt")
            if not path:
                return
            
            with open(path, "rb") as f:
                encrypted = f.read()
            
            decrypted = self.rsa_pair.decrypt(encrypted)
            out = path.replace('.rsa', '.dec')
            
            with open(out, "wb") as f:
                f.write(decrypted)
            
            self.log(f"✓ RSA decrypted: {os.path.basename(path)} → {os.path.basename(out)}")
            self.log(f"  Size: {len(encrypted)} bytes → {len(decrypted)} bytes")
        except Exception as e:
            self.log(f"✗ RSA decryption failed: {e}")
            messagebox.showerror("Error", f"RSA decryption failed:\n{e}")

    # ---------- AES actions ----------
    def on_gen_aes(self):
        try:
            self.aes_key = AESCipher.generate_key(32)
            with open("aes_key.bin", "wb") as f:
                f.write(self.aes_key)
            
            self.log("✓ Generated AES-256 key → aes_key.bin")
            self.log(f"  Key: {base64.b64encode(self.aes_key).decode()[:32]}...")
            self.update_status()
            messagebox.showinfo("Success", "AES-256 key generated successfully!")
        except Exception as e:
            self.log(f"✗ Error generating AES key: {e}")
            messagebox.showerror("Error", f"Failed to generate AES key:\n{e}")

    def on_load_aes(self):
        try:
            path = filedialog.askopenfilename(
                title="Select AES key file",
                filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
            )
            if not path:
                return
            
            with open(path, "rb") as f:
                self.aes_key = f.read()
            
            if len(self.aes_key) not in [16, 24, 32]:
                messagebox.showwarning(
                    "Invalid Key", 
                    f"AES key must be 16, 24, or 32 bytes. Got {len(self.aes_key)} bytes."
                )
                self.aes_key = None
                return
            
            self.log(f"✓ Loaded AES-{len(self.aes_key)*8} key: {os.path.basename(path)}")
            self.update_status()
        except Exception as e:
            self.log(f"✗ Error loading AES key: {e}")
            messagebox.showerror("Error", f"Failed to load AES key:\n{e}")

    def on_aes_encrypt(self):
        if not self.aes_key:
            messagebox.showwarning("No AES Key", "Generate or load an AES key first")
            return
        
        try:
            path = filedialog.askopenfilename(title="Select file to encrypt")
            if not path:
                return
            
            with open(path, "rb") as f:
                data = f.read()
            
            cipher = AESCipher(self.aes_key)
            blob = cipher.encrypt_gcm(data)
            out = path + ".enc"
            
            with open(out, "wb") as f:
                f.write(blob)
            
            self.log(f"✓ AES-GCM encrypted: {os.path.basename(path)} → {os.path.basename(out)}")
            self.log(f"  Size: {len(data)} bytes → {len(blob)} bytes")
            messagebox.showinfo("Success", f"File encrypted successfully!\n{os.path.basename(out)}")
        except Exception as e:
            self.log(f"✗ AES encryption failed: {e}")
            messagebox.showerror("Error", f"AES encryption failed:\n{e}")

    def on_aes_decrypt(self):
        if not self.aes_key:
            messagebox.showwarning("No AES Key", "Generate or load an AES key first")
            return
        
        try:
            path = filedialog.askopenfilename(title="Select .enc file to decrypt")
            if not path:
                return
            
            with open(path, "rb") as f:
                blob = f.read()
            
            cipher = AESCipher(self.aes_key)
            pt = cipher.decrypt_gcm(blob)
            out = path.replace('.enc', '.dec')
            
            with open(out, "wb") as f:
                f.write(pt)
            
            self.log(f"✓ AES-GCM decrypted: {os.path.basename(path)} → {os.path.basename(out)}")
            self.log(f"  Size: {len(blob)} bytes → {len(pt)} bytes")
            messagebox.showinfo("Success", f"File decrypted successfully!\n{os.path.basename(out)}")
        except Exception as e:
            self.log(f"✗ AES decryption failed: {e}")
            messagebox.showerror("Error", f"AES decryption failed:\n{e}")

    # ---------- Hash ----------
    def on_hash(self):
        try:
            path = filedialog.askopenfilename(title="Select file to hash")
            if not path:
                return
            
            with open(path, "rb") as f:
                data = f.read()
            
            alg = self.hash_alg.get()
            h = compute_hash(data, alg=alg)
            
            self.log(f"✓ {alg.upper()}({os.path.basename(path)})")
            self.log(f"  = {h}")
            self.log(f"  File size: {len(data)} bytes")
            
            messagebox.showinfo("Hash Computed", f"{alg.upper()} Hash:\n{h}")
        except Exception as e:
            self.log(f"✗ Hash computation failed: {e}")
            messagebox.showerror("Error", f"Hash computation failed:\n{e}")

    # ---------- Text Encryption Tab Actions ----------
    def on_encryption_type_changed(self, value):
        """Called when user switches between AES and RSA"""
        self.log(f"Switched to {value} encryption mode")
        # Clear fields when switching modes
        self.clear_text_fields()
    
    def on_encrypt_text(self):
        encryption_mode = self.encryption_type.get()
        
        if encryption_mode == "AES":
            self._encrypt_text_aes()
        else:  # RSA
            self._encrypt_text_rsa()
    
    def on_decrypt_text(self):
        encryption_mode = self.encryption_type.get()
        
        if encryption_mode == "AES":
            self._decrypt_text_aes()
        else:  # RSA
            self._decrypt_text_rsa()
    
    def _encrypt_text_aes(self):
        if not self.aes_key:
            messagebox.showwarning("No AES Key", "Generate or load an AES key first")
            return
        
        try:
            plaintext = self.plaintext_input.get("1.0", "end-1c").strip()
            if not plaintext:
                messagebox.showwarning("No Input", "Please enter some plaintext to encrypt")
                return
            
            # Encrypt the text
            cipher = AESCipher(self.aes_key)
            plaintext_bytes = plaintext.encode('utf-8')
            encrypted_blob = cipher.encrypt_gcm(plaintext_bytes)
            
            # Encode to base64 for display
            ciphertext_b64 = base64.b64encode(encrypted_blob).decode('utf-8')
            
            # Display in output
            self.ciphertext_output.delete("1.0", "end")
            self.ciphertext_output.insert("1.0", ciphertext_b64)
            
            self.log(f"✓ Text encrypted (AES): {len(plaintext)} chars → {len(ciphertext_b64)} chars (base64)")
            messagebox.showinfo("Success", "Text encrypted with AES successfully!")
            
        except Exception as e:
            self.log(f"✗ AES text encryption failed: {e}")
            messagebox.showerror("Error", f"AES text encryption failed:\n{e}")
    
    def _decrypt_text_aes(self):
        if not self.aes_key:
            messagebox.showwarning("No AES Key", "Generate or load an AES key first")
            return
        
        try:
            ciphertext_b64 = self.ciphertext_output.get("1.0", "end-1c").strip()
            if not ciphertext_b64:
                messagebox.showwarning("No Input", "Please enter base64 ciphertext to decrypt")
                return
            
            # Decode from base64
            encrypted_blob = base64.b64decode(ciphertext_b64)
            
            # Decrypt
            cipher = AESCipher(self.aes_key)
            plaintext_bytes = cipher.decrypt_gcm(encrypted_blob)
            plaintext = plaintext_bytes.decode('utf-8')
            
            # Display in input field
            self.plaintext_input.delete("1.0", "end")
            self.plaintext_input.insert("1.0", plaintext)
            
            self.log(f"✓ Text decrypted (AES): {len(ciphertext_b64)} chars → {len(plaintext)} chars")
            messagebox.showinfo("Success", "Text decrypted with AES successfully!")
            
        except Exception as e:
            self.log(f"✗ AES text decryption failed: {e}")
            messagebox.showerror("Error", f"AES text decryption failed:\n{e}")
    
    def _encrypt_text_rsa(self):
        if not self.rsa_pair:
            messagebox.showwarning("No RSA Key", "Generate or load an RSA key first")
            return
        
        try:
            plaintext = self.plaintext_input.get("1.0", "end-1c").strip()
            if not plaintext:
                messagebox.showwarning("No Input", "Please enter some plaintext to encrypt")
                return
            
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Check size limit for RSA
            if len(plaintext_bytes) > 190:
                messagebox.showwarning(
                    "Text Too Long",
                    f"RSA can only encrypt up to ~190 bytes.\nYour text is {len(plaintext_bytes)} bytes.\n\nPlease use AES for longer text."
                )
                return
            
            # Encrypt with RSA
            encrypted = self.rsa_pair.encrypt(plaintext_bytes)
            
            # Encode to base64 for display
            ciphertext_b64 = base64.b64encode(encrypted).decode('utf-8')
            
            # Display in output
            self.ciphertext_output.delete("1.0", "end")
            self.ciphertext_output.insert("1.0", ciphertext_b64)
            
            self.log(f"✓ Text encrypted (RSA): {len(plaintext)} chars → {len(ciphertext_b64)} chars (base64)")
            messagebox.showinfo("Success", "Text encrypted with RSA successfully!")
            
        except Exception as e:
            self.log(f"✗ RSA text encryption failed: {e}")
            messagebox.showerror("Error", f"RSA text encryption failed:\n{e}")
    
    def _decrypt_text_rsa(self):
        if not self.rsa_pair:
            messagebox.showwarning("No RSA Key", "Load a private RSA key first")
            return
        
        try:
            ciphertext_b64 = self.ciphertext_output.get("1.0", "end-1c").strip()
            if not ciphertext_b64:
                messagebox.showwarning("No Input", "Please enter base64 ciphertext to decrypt")
                return
            
            # Decode from base64
            encrypted = base64.b64decode(ciphertext_b64)
            
            # Decrypt with RSA
            plaintext_bytes = self.rsa_pair.decrypt(encrypted)
            plaintext = plaintext_bytes.decode('utf-8')
            
            # Display in input field
            self.plaintext_input.delete("1.0", "end")
            self.plaintext_input.insert("1.0", plaintext)
            
            self.log(f"✓ Text decrypted (RSA): {len(ciphertext_b64)} chars → {len(plaintext)} chars")
            messagebox.showinfo("Success", "Text decrypted with RSA successfully!")
            
        except Exception as e:
            self.log(f"✗ RSA text decryption failed: {e}")
            messagebox.showerror("Error", f"RSA text decryption failed:\n{e}")

    def on_load_password_list(self):
        try:
            path = filedialog.askopenfilename(
                title="Select password list file",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not path:
                return
            
            with open(path, "r", encoding='utf-8') as f:
                content = f.read()
            
            # Display in plaintext input
            self.plaintext_input.delete("1.0", "end")
            self.plaintext_input.insert("1.0", content)
            
            # Count lines
            lines = content.strip().split('\n')
            self.log(f"✓ Loaded password list: {os.path.basename(path)} ({len(lines)} entries)")
            messagebox.showinfo("Success", f"Loaded {len(lines)} passwords from file")
            
        except Exception as e:
            self.log(f"✗ Failed to load password list: {e}")
            messagebox.showerror("Error", f"Failed to load password list:\n{e}")

    def on_encrypt_password_list(self):
        if not self.aes_key:
            messagebox.showwarning("No AES Key", "Generate or load an AES key first")
            return
        
        try:
            plaintext = self.plaintext_input.get("1.0", "end-1c").strip()
            if not plaintext:
                messagebox.showwarning("No Input", "Please load or enter a password list first")
                return
            
            # Split into lines (passwords)
            passwords = plaintext.split('\n')
            passwords = [p.strip() for p in passwords if p.strip()]
            
            if not passwords:
                messagebox.showwarning("No Passwords", "No valid passwords found")
                return
            
            # Encrypt each password
            cipher = AESCipher(self.aes_key)
            self.encrypted_password_list = []
            
            for password in passwords:
                password_bytes = password.encode('utf-8')
                encrypted_blob = cipher.encrypt_gcm(password_bytes)
                encrypted_b64 = base64.b64encode(encrypted_blob).decode('utf-8')
                self.encrypted_password_list.append(encrypted_b64)
            
            # Display in output (showing first few)
            output_text = '\n'.join(self.encrypted_password_list[:5])
            if len(self.encrypted_password_list) > 5:
                output_text += f"\n\n... and {len(self.encrypted_password_list) - 5} more entries"
            
            self.ciphertext_output.delete("1.0", "end")
            self.ciphertext_output.insert("1.0", output_text)
            
            self.log(f"✓ Encrypted {len(self.encrypted_password_list)} passwords")
            messagebox.showinfo(
                "Success", 
                f"Encrypted {len(self.encrypted_password_list)} passwords!\n\nClick 'Download Encrypted List' to save."
            )
            
        except Exception as e:
            self.log(f"✗ Password list encryption failed: {e}")
            messagebox.showerror("Error", f"Password list encryption failed:\n{e}")

    def on_download_encrypted_list(self):
        if not self.encrypted_password_list:
            messagebox.showwarning("No Data", "Please encrypt a password list first")
            return
        
        try:
            # Ask user where to save
            path = filedialog.asksaveasfilename(
                title="Save encrypted password list",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not path:
                return
            
            # Write encrypted passwords to file
            with open(path, "w", encoding='utf-8') as f:
                for encrypted_password in self.encrypted_password_list:
                    f.write(encrypted_password + '\n')
            
            self.log(f"✓ Downloaded encrypted list: {os.path.basename(path)} ({len(self.encrypted_password_list)} entries)")
            messagebox.showinfo("Success", f"Encrypted password list saved to:\n{os.path.basename(path)}")
            
        except Exception as e:
            self.log(f"✗ Failed to download encrypted list: {e}")
            messagebox.showerror("Error", f"Failed to save encrypted list:\n{e}")


if __name__ == '__main__':
    app = CryptoGUI()
    app.mainloop()