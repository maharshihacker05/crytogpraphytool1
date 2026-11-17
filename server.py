#!/usr/bin/env python3
"""
SecureMsg v3 - Public-key encrypted messaging (hacker terminal edition)

Flow:
  Receiver: Generate a key-pair in the KEYS page and share the public key (SMPUB-...).
  Sender:   Paste the receiver's public key in ENCRYPT, write a message, get a token.
  Receiver: Load the private key in KEYS, paste the token in DECRYPT.

Crypto: X25519 (ECDH) + HKDF-SHA256 + AES-256-GCM.
The private key is stored as a passphrase-protected PKCS#8 PEM file (.smkey).

pip install cryptography
python secure_msg_gui_v3.py
"""

import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ----------------------------------------------------------------------
# Crypto
# ----------------------------------------------------------------------
PUB_PREFIX = "SMPUB-"
TOKEN_PREFIX = "SMMSG1."
HKDF_INFO = b"SecureMsg v1"
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _raw_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(*RAW)


def public_to_str(pub: X25519PublicKey) -> str:
    return PUB_PREFIX + _b64e(_raw_pub(pub))


def public_from_str(text: str) -> X25519PublicKey:
    text = text.strip()
    if not text.startswith(PUB_PREFIX):
        raise ValueError("Invalid public key. It must start with SMPUB-.")
    try:
        raw = _b64d(text[len(PUB_PREFIX):])
    except ValueError:
        raise ValueError("Public key is not valid base64.")
    if len(raw) != 32:
        raise ValueError("Public key length is wrong.")
    return X25519PublicKey.from_public_bytes(raw)


def _derive_key(shared: bytes, eph_pub: bytes, rec_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO + eph_pub + rec_pub,
    ).derive(shared)


def encrypt_for(recipient: X25519PublicKey, message: str) -> str:
    ephemeral = X25519PrivateKey.generate()
    eph_pub = _raw_pub(ephemeral.public_key())
    rec_pub = _raw_pub(recipient)
    key = _derive_key(ephemeral.exchange(recipient), eph_pub, rec_pub)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    return TOKEN_PREFIX + _b64e(eph_pub + nonce + ciphertext)


def decrypt_with(private: X25519PrivateKey, token: str) -> str:
    token = token.strip()
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError("Invalid token format.")
    try:
        blob = _b64d(token[len(TOKEN_PREFIX):])
    except ValueError:
        raise ValueError("Token is corrupted.")
    if len(blob) < 32 + 12 + 16:
        raise ValueError("Token is too short, it is corrupted.")

    eph_raw, nonce, ciphertext = blob[:32], blob[32:44], blob[44:]
    rec_pub = _raw_pub(private.public_key())
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(eph_raw))
        key = _derive_key(shared, eph_raw, rec_pub)
        plain = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plain.decode("utf-8")
    except (InvalidTag, ValueError):
        raise ValueError("Access denied: wrong key, or the token was tampered with.")


# ----------------------------------------------------------------------
# Terminal theme
# ----------------------------------------------------------------------
BLACK = "#000000"
PANEL = "#050d05"
INPUT = "#020a02"
GREEN = "#00ff41"
GREEN_DIM = "#00b82e"
GREEN_DARK = "#003b10"
BORDER = "#00702a"
AMBER = "#ffb000"
RED = "#ff3b3b"
CYAN = "#00e5ff"

FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_TITLE = ("Consolas", 22, "bold")
FONT_SMALL = ("Consolas", 9)
FONT_HEAD = ("Consolas", 11, "bold")

BANNER = r"""
  ____  _____ ____ _   _ ____  _____   __  __ ____   ____
 / ___|| ____/ ___| | | |  _ \| ____| |  \/  / ___| / ___|
 \___ \|  _|| |   | | | | |_) |  _|   | |\/| \___ \| |  _
  ___) | |__| |___| |_| |  _ <| |___  | |  | |___) | |_| |
 |____/|_____\____|\___/|_| \_\_____| |_|  |_|____/ \____|
"""


def make_button(parent, text, command, primary=False, danger=False):
    fg = GREEN
    bg = BLACK
    hover_bg = GREEN
    hover_fg = BLACK
    if primary:
        bg, fg = GREEN_DARK, GREEN
    if danger:
        fg = RED

    b = tk.Button(
        parent, text=f"[ {text} ]", command=command,
        font=FONT_MONO_BOLD, bg=bg, fg=fg,
        activebackground=hover_bg, activeforeground=hover_fg,
        relief="flat", bd=0, padx=12, pady=6, cursor="hand2",
        highlightthickness=1, highlightbackground=BORDER, highlightcolor=GREEN,
    )

    def on_enter(_e):
        b.configure(bg=hover_bg, fg=hover_fg)

    def on_leave(_e):
        b.configure(bg=bg, fg=fg)

    b.bind("<Enter>", on_enter)
    b.bind("<Leave>", on_leave)
    return b


def make_textbox(parent, height=4):
    return tk.Text(
        parent, height=height, wrap="word", font=FONT_MONO,
        bg=INPUT, fg=GREEN, insertbackground=GREEN,
        selectbackground=GREEN_DIM, selectforeground=BLACK,
        relief="flat", bd=0, padx=10, pady=8,
        highlightthickness=1, highlightbackground=BORDER, highlightcolor=GREEN,
    )


def make_entry(parent):
    return tk.Entry(
        parent, font=FONT_MONO, bg=INPUT, fg=GREEN, insertbackground=GREEN,
        selectbackground=GREEN_DIM, selectforeground=BLACK,
        relief="flat", bd=0, highlightthickness=1,
        highlightbackground=BORDER, highlightcolor=GREEN,
    )


def make_panel(parent, title, hint=None):
    outer = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
    inner = tk.Frame(outer, bg=PANEL)
    inner.pack(fill="both", expand=True, padx=18, pady=14)
    tk.Label(inner, text=f"// {title}", font=FONT_HEAD, bg=PANEL, fg=GREEN).pack(anchor="w")
    if hint:
        tk.Label(inner, text=hint, font=FONT_SMALL, bg=PANEL, fg=GREEN_DIM,
                 wraplength=720, justify="left").pack(anchor="w", pady=(2, 10))
    return outer, inner


def button_row(parent):
    row = tk.Frame(parent, bg=PANEL)
    row.pack(anchor="w", pady=(10, 0))
    return row


def get_text(box):
    return box.get("1.0", "end-1c").strip()


def set_input(box, value):
    box.delete("1.0", "end")
    box.insert("1.0", value)


def set_output(box, value):
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", value)
    box.configure(state="disabled")


def ask_passphrase(parent, title, confirm):
    """Terminal-style passphrase prompt. Returns the passphrase or None."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.configure(bg=BLACK)
    dlg.resizable(False, False)
    dlg.transient(parent)
    result = {"value": None}

    frame = tk.Frame(dlg, bg=PANEL, highlightthickness=1, highlightbackground=GREEN)
    frame.pack(padx=18, pady=18)
    inner = tk.Frame(frame, bg=PANEL)
    inner.pack(padx=26, pady=22)

    tk.Label(inner, text=f"// {title}", font=FONT_HEAD, bg=PANEL, fg=GREEN).pack(anchor="w")
    tk.Label(
        inner,
        text="This passphrase locks your private key. There is no recovery if you forget it.",
        font=FONT_SMALL, bg=PANEL, fg=GREEN_DIM, wraplength=380, justify="left",
    ).pack(anchor="w", pady=(4, 14))

    tk.Label(inner, text="> passphrase (min 8 chars)", font=FONT_SMALL,
             bg=PANEL, fg=GREEN).pack(anchor="w")
    e1 = make_entry(inner)
    e1.configure(show="*")
    e1.pack(fill="x", ipady=6, pady=(4, 10))

    e2 = None
    if confirm:
        tk.Label(inner, text="> confirm passphrase", font=FONT_SMALL,
                 bg=PANEL, fg=GREEN).pack(anchor="w")
        e2 = make_entry(inner)
        e2.configure(show="*")
        e2.pack(fill="x", ipady=6, pady=(4, 10))

    err = tk.Label(inner, text="", font=FONT_SMALL, bg=PANEL, fg=RED)
    err.pack(anchor="w")

    def ok(_event=None):
        pw = e1.get()
        if len(pw) < 8:
            err.configure(text="ERROR: passphrase must be at least 8 characters.")
            return
        if confirm and pw != e2.get():
            err.configure(text="ERROR: passphrases do not match.")
            return
        result["value"] = pw
        dlg.destroy()

    def cancel(_event=None):
        dlg.destroy()

    btns = tk.Frame(inner, bg=PANEL)
    btns.pack(anchor="e", pady=(10, 0))
    make_button(btns, "CANCEL", cancel).pack(side="left", padx=(0, 8))
    make_button(btns, "CONFIRM", ok, primary=True).pack(side="left")

    dlg.bind("<Return>", ok)
    dlg.bind("<Escape>", cancel)
    e1.focus_set()
    dlg.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dlg.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dlg.winfo_height()) // 3
    dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    dlg.wait_visibility()
    dlg.grab_set()
    dlg.wait_window()
    return result["value"]


# ----------------------------------------------------------------------
# App
# ----------------------------------------------------------------------
class SecureMsgApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureMsg // terminal")
        self.geometry("1000x720")
        self.minsize(860, 640)
        self.configure(bg=BLACK)

        self.private_key = None
        self.public_key_str = ""

        self._build_statusbar()

        body = tk.Frame(self, bg=BLACK)
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)

        self.container = tk.Frame(body, bg=BLACK)
        self.container.pack(side="left", fill="both", expand=True)
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        self.pages = {}
        for name, builder in (
            ("keys", self._build_keys_page),
            ("encrypt", self._build_encrypt_page),
            ("decrypt", self._build_decrypt_page),
        ):
            frame = tk.Frame(self.container, bg=BLACK)
            frame.grid(row=0, column=0, sticky="nsew")
            builder(frame)
            self.pages[name] = frame

        self.show_page("keys")
        self._refresh_key_state()
        self._status("system ready. generate a key-pair to begin.", "info")

    # ---------- chrome ----------
    def _build_statusbar(self):
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(
            self, textvariable=self.status_var, anchor="w",
            bg=PANEL, fg=GREEN_DIM, font=FONT_SMALL, padx=14, pady=6,
        )
        self.status_label.pack(fill="x", side="bottom")

    def _status(self, text, kind="info"):
        colors = {"ok": GREEN, "error": RED, "warn": AMBER, "info": GREEN_DIM}
        self.status_var.set(f"> {text}")
        self.status_label.configure(fg=colors.get(kind, GREEN_DIM))

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=PANEL, width=230, highlightthickness=1, highlightbackground=BORDER)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="SECUREMSG", font=FONT_TITLE, bg=PANEL, fg=GREEN).pack(anchor="w", padx=20, pady=(24, 0))
        tk.Label(side, text="encrypted channel v3", font=FONT_SMALL, bg=PANEL, fg=GREEN_DIM).pack(anchor="w", padx=22, pady=(0, 26))

        self.nav_buttons = {}
        for key, label in (("keys", "KEYS"), ("encrypt", "ENCRYPT"), ("decrypt", "DECRYPT")):
            b = tk.Button(
                side, text=f"  > {label}", anchor="w", font=FONT_MONO_BOLD,
                bg=PANEL, fg=GREEN_DIM, activebackground=GREEN_DARK, activeforeground=GREEN,
                relief="flat", bd=0, padx=20, pady=10, cursor="hand2",
                command=lambda k=key: self.show_page(k),
            )
            b.pack(fill="x")
            self.nav_buttons[key] = b

        tk.Frame(side, bg=PANEL).pack(fill="both", expand=True)
        self.key_badge = tk.Label(side, text="", font=FONT_SMALL, bg=PANEL, fg=AMBER,
                                  anchor="w", justify="left")
        self.key_badge.pack(anchor="w", padx=20, pady=22)

    def show_page(self, name):
        self.pages[name].tkraise()
        for key, btn in self.nav_buttons.items():
            active = key == name
            btn.configure(
                bg=GREEN_DARK if active else PANEL,
                fg=GREEN if active else GREEN_DIM,
            )

    def _page_header(self, parent, title, subtitle):
        tk.Label(parent, text=f"{title.upper()}_", font=FONT_TITLE, bg=BLACK, fg=GREEN).pack(anchor="w", padx=30, pady=(24, 0))
        tk.Label(parent, text=f"$ {subtitle}", font=FONT_MONO, bg=BLACK, fg=GREEN_DIM).pack(anchor="w", padx=32, pady=(2, 16))

    def _page_body(self, parent):
        body = tk.Frame(parent, bg=BLACK)
        body.pack(fill="both", expand=True, padx=30, pady=(0, 18))
        return body

    # ---------- KEYS page ----------
    def _build_keys_page(self, parent):
        self._page_header(parent, "keys", "manage your X25519 key-pair")
        body = self._page_body(parent)

        panel, inner = make_panel(
            body, "public key",
            "Share this with anyone who wants to send you encrypted messages. It is safe to share.",
        )
        panel.pack(fill="x", pady=(0, 14))
        self.pub_box = make_textbox(inner, height=3)
        self.pub_box.pack(fill="x")
        row = button_row(inner)
        make_button(row, "COPY PUBLIC KEY", lambda: self._copy(self.pub_box, "Public key")).pack(side="left")
        make_button(row, "SAVE .smpub", self._save_public).pack(side="left", padx=8)

        panel, inner = make_panel(
            body, "key management",
            "Never share your private key. It is stored as a passphrase-locked .smkey file.",
        )
        panel.pack(fill="x")
        row = button_row(inner)
        make_button(row, "GENERATE NEW KEY-PAIR", self._generate_keypair, primary=True).pack(side="left")
        make_button(row, "LOAD PRIVATE KEY", self._load_private).pack(side="left", padx=8)

    # ---------- ENCRYPT page ----------
    def _build_encrypt_page(self, parent):
        self._page_header(parent, "encrypt", "lock a message with the receiver's public key")
        body = self._page_body(parent)

        panel, inner = make_panel(
            body, "01 // receiver public key",
            "Paste the receiver's SMPUB- key, or load their .smpub file.",
        )
        panel.pack(fill="x", pady=(0, 12))
        self.rec_box = make_textbox(inner, height=2)
        self.rec_box.pack(fill="x")
        row = button_row(inner)
        make_button(row, "LOAD .smpub FILE", self._load_recipient).pack(side="left")
        make_button(row, "CLEAR", lambda: set_input(self.rec_box, "")).pack(side="left", padx=8)

        panel, inner = make_panel(body, "02 // message")
        panel.pack(fill="x", pady=(0, 12))
        self.enc_input = make_textbox(inner, height=4)
        self.enc_input.pack(fill="x")
        self.enc_input.bind("<Control-Return>", lambda e: (self._encrypt(), "break")[1])
        row = button_row(inner)
        make_button(row, "ENCRYPT  (Ctrl+Enter)", self._encrypt, primary=True).pack(side="left")
        make_button(row, "CLEAR", self._clear_encrypt).pack(side="left", padx=8)

        panel, inner = make_panel(
            body, "03 // encrypted token",
            "Send this token to the receiver. Only their private key can open it.",
        )
        panel.pack(fill="both", expand=True)
        self.token_out = make_textbox(inner, height=4)
        self.token_out.pack(fill="both", expand=True)
        set_output(self.token_out, "")
        row = button_row(inner)
        make_button(row, "COPY TOKEN", lambda: self._copy(self.token_out, "Token")).pack(side="left")
        make_button(row, "SAVE .txt", self._save_token).pack(side="left", padx=8)

    # ---------- DECRYPT page ----------
    def _build_decrypt_page(self, parent):
        self._page_header(parent, "decrypt", "open a message with your private key")
        body = self._page_body(parent)

        self.dec_warn = tk.Label(body, text="", font=FONT_SMALL, bg=BLACK, fg=AMBER)
        self.dec_warn.pack(anchor="w", pady=(0, 8))

        panel, inner = make_panel(
            body, "01 // encrypted token",
            "Paste the token you received, or load it from a file.",
        )
        panel.pack(fill="x", pady=(0, 12))
        self.dec_token = make_textbox(inner, height=4)
        self.dec_token.pack(fill="x")
        self.dec_token.bind("<Control-Return>", lambda e: (self._decrypt(), "break")[1])
        row = button_row(inner)
        make_button(row, "LOAD FROM FILE", self._load_token).pack(side="left")
        make_button(row, "DECRYPT  (Ctrl+Enter)", self._decrypt, primary=True).pack(side="left", padx=8)
        make_button(row, "CLEAR", self._clear_decrypt).pack(side="left")

        panel, inner = make_panel(body, "02 // decrypted message")
        panel.pack(fill="both", expand=True)
        self.dec_output = make_textbox(inner, height=5)
        self.dec_output.pack(fill="both", expand=True)
        set_output(self.dec_output, "")
        row = button_row(inner)
        make_button(row, "COPY MESSAGE", lambda: self._copy(self.dec_output, "Message")).pack(side="left")

    # ---------- state ----------
    def _refresh_key_state(self):
        if self.private_key:
            self.key_badge.configure(text="[ KEY LOADED ]", fg=GREEN)
            self.dec_warn.configure(text="")
            set_output(self.pub_box, self.public_key_str)
        else:
            self.key_badge.configure(text="[ NO KEY LOADED ]", fg=AMBER)
            self.dec_warn.configure(text="! no private key loaded. go to KEYS to load one.")
            set_output(self.pub_box, "No key-pair yet. Click GENERATE NEW KEY-PAIR.")

    # ---------- key actions ----------
    def _generate_keypair(self):
        pw = ask_passphrase(self, "generate key-pair", confirm=True)
        if not pw:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".smkey",
            filetypes=[("SecureMsg private key", "*.smkey")],
            title="Save private key",
        )
        if not path:
            self._status("key generation cancelled.", "warn")
            return

        priv = X25519PrivateKey.generate()
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(pw.encode("utf-8")),
        )
        with open(path, "wb") as f:
            f.write(pem)

        self.private_key = priv
        self.public_key_str = public_to_str(priv.public_key())
        self._refresh_key_state()
        self._status(f"key-pair generated. private key saved to {path}", "ok")

    def _load_private(self):
        path = filedialog.askopenfilename(
            filetypes=[("SecureMsg private key", "*.smkey"), ("All files", "*.*")],
            title="Load private key",
        )
        if not path:
            return
        pw = ask_passphrase(self, "unlock private key", confirm=False)
        if not pw:
            return
        try:
            with open(path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=pw.encode("utf-8"))
        except (ValueError, TypeError, OSError):
            messagebox.showerror("Access denied", "Wrong passphrase, or the key file is corrupted.")
            self._status("private key failed to load.", "error")
            return
        if not isinstance(priv, X25519PrivateKey):
            messagebox.showerror("Invalid file", "This is not a SecureMsg key file.")
            return

        self.private_key = priv
        self.public_key_str = public_to_str(priv.public_key())
        self._refresh_key_state()
        self._status("private key unlocked.", "ok")

    def _save_public(self):
        if not self.public_key_str:
            self._status("generate a key-pair first.", "warn")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".smpub",
            filetypes=[("SecureMsg public key", "*.smpub")],
            title="Save public key",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.public_key_str)
        self._status(f"public key saved to {path}", "ok")

    # ---------- encrypt actions ----------
    def _load_recipient(self):
        path = filedialog.askopenfilename(
            filetypes=[("SecureMsg public key", "*.smpub"), ("All files", "*.*")],
            title="Load receiver public key",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                set_input(self.rec_box, f.read().strip())
        except OSError as e:
            messagebox.showerror("File error", f"Could not read file:\n{e}")
            return
        self._status("receiver public key loaded.", "ok")

    def _encrypt(self):
        rec_text = get_text(self.rec_box)
        message = get_text(self.enc_input)
        if not rec_text:
            messagebox.showwarning("Missing key", "Paste the receiver's public key first.")
            return
        if not message:
            messagebox.showwarning("Empty message", "Write a message first.")
            return
        try:
            recipient = public_from_str(rec_text)
        except ValueError as e:
            messagebox.showerror("Invalid key", str(e))
            return
        token = encrypt_for(recipient, message)
        set_output(self.token_out, token)
        self._status("message encrypted. send the token to the receiver.", "ok")

    def _clear_encrypt(self):
        set_input(self.enc_input, "")
        set_output(self.token_out, "")
        self._status("message cleared.", "info")

    def _save_token(self):
        token = get_text(self.token_out)
        if not token:
            self._status("encrypt a message first.", "warn")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save token",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(token)
        self._status(f"token saved to {path}", "ok")

    # ---------- decrypt actions ----------
    def _load_token(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Load token file",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                set_input(self.dec_token, f.read().strip())
        except OSError as e:
            messagebox.showerror("File error", f"Could not read file:\n{e}")
            return
        self._status("token file loaded.", "ok")

    def _decrypt(self):
        token = get_text(self.dec_token)
        if not self.private_key:
            messagebox.showwarning("No key", "Load your private key in the KEYS page first.")
            self.show_page("keys")
            return
        if not token:
            messagebox.showwarning("Empty token", "Paste a token first.")
            return
        try:
            plain = decrypt_with(self.private_key, token)
        except ValueError as e:
            set_output(self.dec_output, "")
            self._status("decryption failed.", "error")
            messagebox.showerror("Decryption failed", str(e))
            return
        set_output(self.dec_output, plain)
        self._status("message decrypted successfully.", "ok")

    def _clear_decrypt(self):
        set_input(self.dec_token, "")
        set_output(self.dec_output, "")
        self._status("decrypt panel cleared.", "info")

    # ---------- shared ----------
    def _copy(self, box, label):
        text = get_text(box)
        if not text or text.startswith("No key-pair"):
            self._status(f"{label.lower()} is empty.", "warn")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status(f"{label.lower()} copied to clipboard.", "ok")


if __name__ == "__main__":
    SecureMsgApp().mainloop()
