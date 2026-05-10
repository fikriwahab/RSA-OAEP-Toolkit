"""Tkinter front-end for RSA-OAEP key generation, encryption, and decryption."""

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rsa import generate_keypair
from crypto import encrypt_file, decrypt_file
from keyio import save_public_key, save_private_key, load_key, to_public_key, to_private_key
from oaep import DecryptionError


APP_TITLE = "RSA-OAEP-256 File Tool"


def _assets_dir():
    """Return the directory that holds bundled assets at runtime.

    PyInstaller extracts data files to a temporary directory exposed through
    sys._MEIPASS. When running from source, assets live one level above the
    src directory.
    """
    base = getattr(sys, "_MEIPASS", None)
    if base is not None:
        return os.path.join(base, "assets")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")


ASSETS_DIR = _assets_dir()
LOGO_PATH = os.path.join(ASSETS_DIR, "logo.png")


def _load_image(path, subsample=None):
    """Load a PNG into a PhotoImage, optionally downscaling by an integer factor."""
    if not os.path.isfile(path):
        return None
    try:
        image = tk.PhotoImage(file=path)
    except tk.TclError:
        return None
    if subsample is not None and subsample > 1:
        image = image.subsample(subsample, subsample)
    return image


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("700x520")
        root.minsize(560, 460)
        self.header_logo = _load_image(LOGO_PATH, subsample=8)
        self.about_logo = _load_image(LOGO_PATH, subsample=3)
        if self.header_logo is not None:
            try:
                root.iconphoto(True, self.header_logo)
            except tk.TclError:
                pass
        self._build_header(root)
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._build_keygen_tab(notebook)
        self._build_encrypt_tab(notebook)
        self._build_decrypt_tab(notebook)
        self._build_about_tab(notebook)

    def _build_header(self, root):
        header = ttk.Frame(root, padding=(12, 10))
        header.pack(fill="x")
        if self.header_logo is not None:
            ttk.Label(header, image=self.header_logo).pack(side="left", padx=(0, 12))
        text_frame = ttk.Frame(header)
        text_frame.pack(side="left", fill="x", expand=True)
        ttk.Label(text_frame, text=APP_TITLE, font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        ttk.Label(
            text_frame,
            text="From-scratch RSA encryption with OAEP padding (SHA-256 + MGF1)",
        ).pack(anchor="w")
        ttk.Separator(root, orient="horizontal").pack(fill="x", padx=8, pady=(4, 4))

    # Tab construction

    def _build_keygen_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Generate Keys")
        self.keygen_pub_var = tk.StringVar()
        self.keygen_priv_var = tk.StringVar()
        self.keygen_bits_var = tk.IntVar(value=2048)
        ttk.Label(frame, text="Key size (bits):").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Spinbox(
            frame, from_=512, to=4096, increment=256,
            textvariable=self.keygen_bits_var, width=10,
        ).grid(row=0, column=1, sticky="w")
        self._row_with_browse(frame, 1, "Public key output:", self.keygen_pub_var, self._pick_save_pub)
        self._row_with_browse(frame, 2, "Private key output:", self.keygen_priv_var, self._pick_save_priv)
        self.keygen_button = ttk.Button(frame, text="Generate", command=self._on_keygen)
        self.keygen_button.grid(row=3, column=0, columnspan=3, pady=10)
        self.keygen_status = ttk.Label(frame, text="")
        self.keygen_status.grid(row=4, column=0, columnspan=3, sticky="w")
        frame.columnconfigure(1, weight=1)

    def _build_encrypt_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Encrypt")
        self.enc_input_var = tk.StringVar()
        self.enc_key_var = tk.StringVar()
        self.enc_output_var = tk.StringVar()
        self._row_with_browse(frame, 0, "Plaintext file:", self.enc_input_var, self._pick_enc_input)
        self._row_with_browse(frame, 1, "Public key file:", self.enc_key_var, self._pick_enc_key)
        self._row_with_browse(frame, 2, "Ciphertext output:", self.enc_output_var, self._pick_enc_output)
        self.enc_button = ttk.Button(frame, text="Encrypt", command=self._on_encrypt)
        self.enc_button.grid(row=3, column=0, columnspan=3, pady=10)
        self.enc_progress = ttk.Progressbar(frame, mode="determinate", maximum=100)
        self.enc_progress.grid(row=4, column=0, columnspan=3, sticky="we", pady=4)
        self.enc_status = ttk.Label(frame, text="")
        self.enc_status.grid(row=5, column=0, columnspan=3, sticky="w")
        frame.columnconfigure(1, weight=1)

    def _build_decrypt_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Decrypt")
        self.dec_input_var = tk.StringVar()
        self.dec_key_var = tk.StringVar()
        self.dec_output_var = tk.StringVar()
        self._row_with_browse(frame, 0, "Ciphertext file:", self.dec_input_var, self._pick_dec_input)
        self._row_with_browse(frame, 1, "Private key file:", self.dec_key_var, self._pick_dec_key)
        self._row_with_browse(frame, 2, "Plaintext output:", self.dec_output_var, self._pick_dec_output)
        self.dec_button = ttk.Button(frame, text="Decrypt", command=self._on_decrypt)
        self.dec_button.grid(row=3, column=0, columnspan=3, pady=10)
        self.dec_progress = ttk.Progressbar(frame, mode="determinate", maximum=100)
        self.dec_progress.grid(row=4, column=0, columnspan=3, sticky="we", pady=4)
        self.dec_status = ttk.Label(frame, text="")
        self.dec_status.grid(row=5, column=0, columnspan=3, sticky="w")
        frame.columnconfigure(1, weight=1)

    def _build_about_tab(self, notebook):
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="About")
        if self.about_logo is not None:
            ttk.Label(frame, image=self.about_logo).pack(pady=(8, 12))
        message = (
            APP_TITLE + "\n\n"
            "A from-scratch implementation of RSA encryption with OAEP padding\n"
            "(SHA-256 + MGF1) for general-purpose file encryption.\n\n"
            "Highlights:\n"
            "  - 2048-bit RSA key generation with Miller-Rabin primality testing\n"
            "  - OAEP padding following PKCS #1 v2.2 (RFC 8017)\n"
            "  - Pure Python SHA-256 implementation (FIPS 180-4)\n"
            "  - CRT-based decryption for performance\n"
            "  - Streaming I/O so large files do not need to fit in memory\n"
        )
        text_widget = tk.Text(frame, wrap="word", padx=10, pady=10, height=10)
        text_widget.insert("1.0", message)
        text_widget.configure(state="disabled")
        text_widget.pack(fill="both", expand=True)

    # Layout helper

    def _row_with_browse(self, frame, row, label, variable, command):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=variable).grid(row=row, column=1, sticky="we", padx=4)
        ttk.Button(frame, text="Browse...", command=command).grid(row=row, column=2)

    # File pickers

    def _pick_save_pub(self):
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key file", "*.key"), ("All files", "*.*")])
        if path:
            self.keygen_pub_var.set(path)

    def _pick_save_priv(self):
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key file", "*.key"), ("All files", "*.*")])
        if path:
            self.keygen_priv_var.set(path)

    def _pick_enc_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.enc_input_var.set(path)

    def _pick_enc_key(self):
        path = filedialog.askopenfilename(filetypes=[("Key file", "*.key"), ("All files", "*.*")])
        if path:
            self.enc_key_var.set(path)

    def _pick_enc_output(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.enc_output_var.set(path)

    def _pick_dec_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.dec_input_var.set(path)

    def _pick_dec_key(self):
        path = filedialog.askopenfilename(filetypes=[("Key file", "*.key"), ("All files", "*.*")])
        if path:
            self.dec_key_var.set(path)

    def _pick_dec_output(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.dec_output_var.set(path)

    # Key generation

    def _on_keygen(self):
        pub_path = self.keygen_pub_var.get().strip()
        priv_path = self.keygen_priv_var.get().strip()
        bits = self.keygen_bits_var.get()
        if not pub_path or not priv_path:
            messagebox.showerror("Missing input", "Please choose output paths for both keys.")
            return
        self.keygen_button.configure(state="disabled")
        self.keygen_status.configure(text="Generating " + str(bits) + "-bit key pair...")
        thread = threading.Thread(target=self._run_keygen, args=(pub_path, priv_path, bits), daemon=True)
        thread.start()

    def _run_keygen(self, pub_path, priv_path, bits):
        start = time.time()
        try:
            public_key, private_key = generate_keypair(bits)
            save_public_key(pub_path, public_key)
            save_private_key(priv_path, private_key)
        except Exception as exc:
            self.root.after(0, self._keygen_error, str(exc))
            return
        elapsed = time.time() - start
        self.root.after(0, self._keygen_done, elapsed)

    def _keygen_done(self, elapsed):
        self.keygen_button.configure(state="normal")
        self.keygen_status.configure(text="Key pair generated in " + format(elapsed, ".2f") + " seconds.")
        messagebox.showinfo("Done", "Key pair written successfully.")

    def _keygen_error(self, message):
        self.keygen_button.configure(state="normal")
        self.keygen_status.configure(text="Error: " + message)
        messagebox.showerror("Key generation failed", message)

    # Encryption

    def _on_encrypt(self):
        in_path = self.enc_input_var.get().strip()
        key_path = self.enc_key_var.get().strip()
        out_path = self.enc_output_var.get().strip()
        if not (in_path and key_path and out_path):
            messagebox.showerror("Missing input", "Please choose all three files.")
            return
        try:
            loaded = load_key(key_path)
            public_key = to_public_key(loaded)
        except Exception as exc:
            messagebox.showerror("Invalid key", str(exc))
            return
        self.enc_button.configure(state="disabled")
        self.enc_progress.configure(value=0)
        self.enc_status.configure(text="Encrypting...")
        thread = threading.Thread(target=self._run_encrypt, args=(in_path, out_path, public_key), daemon=True)
        thread.start()

    def _run_encrypt(self, in_path, out_path, public_key):
        try:
            encrypt_file(in_path, out_path, public_key, self._enc_progress_callback)
        except Exception as exc:
            self.root.after(0, self._enc_error, str(exc))
            return
        self.root.after(0, self._enc_done, out_path)

    def _enc_progress_callback(self, current, total):
        if total <= 0:
            percent = 100
        else:
            percent = (current * 100) // total
        self.root.after(0, self._update_enc_progress, percent)

    def _update_enc_progress(self, percent):
        self.enc_progress.configure(value=percent)
        self.enc_status.configure(text="Encrypting: " + str(percent) + "%")

    def _enc_done(self, out_path):
        self.enc_button.configure(state="normal")
        self.enc_progress.configure(value=100)
        self.enc_status.configure(text="Encryption complete.")
        messagebox.showinfo("Done", "Encrypted file written to:\n" + out_path)

    def _enc_error(self, message):
        self.enc_button.configure(state="normal")
        self.enc_status.configure(text="Error: " + message)
        messagebox.showerror("Encryption failed", message)

    # Decryption

    def _on_decrypt(self):
        in_path = self.dec_input_var.get().strip()
        key_path = self.dec_key_var.get().strip()
        out_path = self.dec_output_var.get().strip()
        if not (in_path and key_path and out_path):
            messagebox.showerror("Missing input", "Please choose all three files.")
            return
        try:
            loaded = load_key(key_path)
            private_key = to_private_key(loaded)
        except Exception as exc:
            messagebox.showerror("Invalid key", str(exc))
            return
        self.dec_button.configure(state="disabled")
        self.dec_progress.configure(value=0)
        self.dec_status.configure(text="Decrypting...")
        thread = threading.Thread(target=self._run_decrypt, args=(in_path, out_path, private_key), daemon=True)
        thread.start()

    def _run_decrypt(self, in_path, out_path, private_key):
        try:
            decrypt_file(in_path, out_path, private_key, self._dec_progress_callback)
        except DecryptionError as exc:
            self.root.after(0, self._dec_error, "Decryption failed: " + str(exc))
            return
        except Exception as exc:
            self.root.after(0, self._dec_error, str(exc))
            return
        self.root.after(0, self._dec_done, out_path)

    def _dec_progress_callback(self, current, total):
        if total <= 0:
            percent = 100
        else:
            percent = (current * 100) // total
        self.root.after(0, self._update_dec_progress, percent)

    def _update_dec_progress(self, percent):
        self.dec_progress.configure(value=percent)
        self.dec_status.configure(text="Decrypting: " + str(percent) + "%")

    def _dec_done(self, out_path):
        self.dec_button.configure(state="normal")
        self.dec_progress.configure(value=100)
        self.dec_status.configure(text="Decryption complete.")
        messagebox.showinfo("Done", "Decrypted file written to:\n" + out_path)

    def _dec_error(self, message):
        self.dec_button.configure(state="normal")
        self.dec_status.configure(text="Error: " + message)
        messagebox.showerror("Decryption failed", message)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
