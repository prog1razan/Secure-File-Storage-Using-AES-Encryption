import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import os

KEY_FILE = "secret.key"
USER_FILE = "users.txt"

is_dark_mode = True  # default theme mode

# ---------- Crypto ----------
def generate_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())

def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    out_path = filepath + ".enc"
    with open(out_path, "wb") as f:
        f.write(encrypted)
    return out_path

def decrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)
        out_path = filepath.replace(".enc", "_decrypted")
        with open(out_path, "wb") as f:
            f.write(decrypted)
        return out_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed: {e}")
        return None

# ---------- Auth ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    if not os.path.exists(USER_FILE):
        open(USER_FILE, "w").close()
    with open(USER_FILE, "r") as f:
        for line in f:
            user, _ = line.strip().split(":")
            if user == username:
                return False
    with open(USER_FILE, "a") as f:
        f.write(f"{username}:{hash_password(password)}\n")
    return True

def authenticate_user(username, password):
    if not os.path.exists(USER_FILE):
        return False
    with open(USER_FILE, "r") as f:
        for line in f:
            user, pwd = line.strip().split(":")
            if user == username and pwd == hash_password(password):
                return True
    return False

# ---------- Theme ----------
def apply_style(root, theme):
    style = ttk.Style(root)
    style.theme_use("clam")

    if theme == "dark":
        root.configure(bg="#1e1e1e")
        root.tk_setPalette(background="#1e1e1e", foreground="#ffffff")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 11))
        style.configure("TButton", background="#3a3a3a", foreground="#ffffff", padding=8, font=("Segoe UI", 11))
        style.map("TButton", background=[("active", "#5a5a5a")])
        style.configure("TEntry", fieldbackground="#2c2c2c", foreground="#ffffff", font=("Segoe UI", 11))
    else:
        root.configure(bg="#f0f0f0")
        root.tk_setPalette(background="#f0f0f0", foreground="#000000")
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", foreground="#000000", font=("Segoe UI", 11))
        style.configure("TButton", background="#e0e0e0", foreground="#000000", padding=8, font=("Segoe UI", 11))
        style.map("TButton", background=[("active", "#d0d0d0")])
        style.configure("TEntry", fieldbackground="#ffffff", foreground="#000000", font=("Segoe UI", 11))

# ---------- Main App ----------
def main_app():
    login_window.destroy()
    generate_key()

    root = tk.Tk()
    root.title("AES File Encryptor/Decryptor")
    root.attributes('-fullscreen', True)

    uploaded_file = tk.StringVar()
    theme_button_text = tk.StringVar(value="Switch to Light Mode")

    frame = ttk.Frame(root, padding=40)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    def toggle_theme():
        global is_dark_mode
        is_dark_mode = not is_dark_mode
        theme = "dark" if is_dark_mode else "light"
        theme_button_text.set("Switch to Light Mode" if is_dark_mode else "Switch to Dark Mode")
        apply_style(root, theme)

    def upload_file():
        path = filedialog.askopenfilename()
        if path:
            uploaded_file.set(path)
            messagebox.showinfo("Uploaded", path)

    def encrypt_file_action():
        path = uploaded_file.get()
        if path:
            out = encrypt_file(path)
            messagebox.showinfo("Encrypted", f"Saved: {out}")
        else:
            messagebox.showwarning("No File", "Please upload a file first.")

    def decrypt_file_action():
        path = uploaded_file.get()
        if path:
            out = decrypt_file(path)
            if out:
                messagebox.showinfo("Decrypted", f"Saved: {out}")
        else:
            messagebox.showwarning("No File", "Please upload a file first.")

    ttk.Label(frame, text="Secure Your File!", font=("Segoe UI", 20, "bold")).pack(pady=10)
    ttk.Button(frame, text="Upload File", command=upload_file, width=30).pack(pady=5)
    ttk.Button(frame, text="Encrypt File", command=encrypt_file_action, width=30).pack(pady=5)
    ttk.Button(frame, text="Decrypt File", command=decrypt_file_action, width=30).pack(pady=5)
    ttk.Button(frame, textvariable=theme_button_text, command=toggle_theme, width=30).pack(pady=5)
    ttk.Button(frame, text="Exit", command=root.destroy, width=30).pack(pady=10)

    apply_style(root, "dark" if is_dark_mode else "light")
    root.mainloop()

# ---------- Sign Up ----------
def signup_screen():
    signup = tk.Toplevel()
    signup.title("Sign Up")
    signup.geometry("350x200")
    apply_style(signup, "dark" if is_dark_mode else "light")

    frame = ttk.Frame(signup, padding=20)
    frame.pack(expand=True)

    ttk.Label(frame, text="New Username").pack(pady=5)
    user_entry = ttk.Entry(frame)
    user_entry.pack()

    ttk.Label(frame, text="New Password").pack(pady=5)
    pass_entry = ttk.Entry(frame, show="*")
    pass_entry.pack()

    def register():
        user = user_entry.get()
        pwd = pass_entry.get()
        if register_user(user, pwd):
            messagebox.showinfo("Success", "Account created.")
            signup.destroy()
        else:
            messagebox.showerror("Error", "Username already exists.")

    ttk.Button(frame, text="Create Account", command=register).pack(pady=10)

# ---------- Login ----------
def login_screen():
    global login_window
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("350x250")
    apply_style(login_window, "dark" if is_dark_mode else "light")

    frame = ttk.Frame(login_window, padding=20)
    frame.pack(expand=True)

    ttk.Label(frame, text="Username").pack(pady=5)
    user_entry = ttk.Entry(frame)
    user_entry.pack()

    ttk.Label(frame, text="Password").pack(pady=5)
    pass_entry = ttk.Entry(frame, show="*")
    pass_entry.pack()

    def try_login():
        user = user_entry.get()
        pwd = pass_entry.get()
        if authenticate_user(user, pwd):
            main_app()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials.")

    ttk.Button(frame, text="Login", command=try_login).pack(pady=10)
    ttk.Button(frame, text="Sign Up", command=signup_screen).pack()

    login_window.mainloop()

# ---------- Run ----------
login_screen()
