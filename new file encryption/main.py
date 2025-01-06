import tkinter as tk
from tkinter import filedialog, messagebox
from register import register_user
from login import login_user
from encryptor import FileEncryptor

class Application:
    def __init__(self, master):
        self.master = master
        master.title("User  Authentication")
        master.geometry("400x300")  # Increased window size for login/registration
        #master.configure(bg="#f0f0f0")  # Light gray background
        master.configure(bg="#ADD8E6")  # Light blue background for main window

        # User Registration/Login Frame
        self.frame = tk.Frame(master, bg="#E6E6FA")
        self.frame.pack(pady=20)

        self.label = tk.Label(self.frame, text="Welcome to File Encryptor/Decryptor", font=("Helvetica", 16, "bold"), bg="#f0f0f0", fg="#333")
        self.label.pack()

        self.username_label = tk.Label(self.frame, text="Username:", bg="#f0f0f0", fg="#333")
        self.username_label.pack()
        self.username_entry = tk.Entry(self.frame, bg="#fff", fg="#333")
        self.username_entry.pack(pady=5)

        self.password_label = tk.Label(self.frame, text="Password:", bg="#f0f0f0", fg="#333")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.frame, show='*', bg="#fff", fg="#333")
        self.password_entry.pack(pady=5)

        self.register_button = tk.Button(self.frame, text="Register", command=self.register, bg="#4CAF50", fg="white", font=("Helvetica", 10))
        self.register_button.pack(pady=5)

        self.login_button = tk.Button(self.frame, text="Login", command=self.login, bg="#2196F3", fg="white", font=("Helvetica", 10))
        self.login_button.pack(pady=5)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            register_user(username, password)
            messagebox.showinfo("Success", "User  registered successfully!")
        else:
            messagebox.showwarning("Input Error", "Please enter both username and password.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if login_user(username, password):
            messagebox.showinfo("Success", "Login successful!")
            self.open_file_frame()  # Open the file encryption/decryption frame
        else:
            messagebox.showwarning("Login Error", "Invalid username or password.")

    def open_file_frame(self):
        # Create a new window for file encryption/decryption
        self.file_window = tk.Toplevel(self.master)
        self.file_window.title("File Encryptor/Decryptor")
        self.file_window.geometry("400x300")  # Increased window size for file operations
        #self.file_window.configure(bg="#f0f0f0")
        self.file_window.configure(bg="#ADD8E6")  # Light sky blue background for file window

        # File Encryption/Decryption Frame
        self.file_frame = tk.Frame(self.file_window, bg="#87CEFA")
        self.file_frame.pack(pady=20)

        self.file_label = tk.Label(self.file_frame, text="Select a file to encrypt or decrypt:", bg="#f0f0f0", fg="#333")
        self.file_label.pack()

        self.file_path = tk.StringVar()
        self.file_entry = tk.Entry(self.file_frame, textvariable=self.file_path, width=60, bg="#fff", fg="#333")
        self.file_entry.pack(pady=5)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file, bg="#FF9800", fg="white", font=("Helvetica", 10))
        self.browse_button.pack(pady=5)

        self.key_label = tk.Label(self.file_frame, text="Enter 16-byte ASCII Key:", bg="#f0f0f0", fg="#333")
        self.key_label.pack()
        self.key_entry = tk.Entry(self.file_frame, bg="#fff", fg="#333")
        self.key_entry.pack(pady=5)

        self.encrypt_button = tk.Button(self.file_frame, text="Encrypt", command=self.encrypt_file, bg="#4CAF50", fg="white", font=("Helvetica", 10))
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(self.file_frame, text="Decrypt", command=self.decrypt_file, bg="#F44336", fg="white", font=("Helvetica", 10))
        self.decrypt_button.pack(pady=5)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def encrypt_file(self):
        file_name = self.file_path.get()
        key = self.key_entry.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showwarning("Key Error", "Key must be 16 bytes long.")
            return
        FileEncryptor.encrypt_file(file_name, key)
        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        file_name = self.file_path.get()  # Use the original file name
        if not file_name.endswith('.enc'):
            file_name += '.enc'  # Append .enc only if it is not already there
        key = self.key_entry.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showwarning("Key Error", "Key must be 16 bytes long.")
            return
        try:
            FileEncryptor.decrypt_file(file_name, key)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except FileNotFoundError:
            messagebox.showerror("File Not Found", f"The file {file_name} does not exist.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()