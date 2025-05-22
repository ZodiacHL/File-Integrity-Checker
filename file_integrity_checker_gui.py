import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib
import os

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file:\n{e}")
        return None

def select_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)

def generate_hash():
    file_path = entry_file.get().strip()
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return
    hash_result = hash_file(file_path)
    if hash_result:
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, f"SHA-256 Hash:\n{hash_result}\n")

def save_hash():
    hash_text = output_box.get("1.0", tk.END).strip()
    if not hash_text:
        messagebox.showwarning("Warning", "No hash to save.")
        return
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if save_path:
        try:
            with open(save_path, "w") as f:
                f.write(hash_text.splitlines()[-1])  # only save the hash
            messagebox.showinfo("Saved", "Hash saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save hash:\n{e}")

def compare_hash():
    file_path = entry_file.get().strip()
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return

    hash_path = filedialog.askopenfilename(title="Select saved hash file", filetypes=[("Text Files", "*.txt")])
    if not hash_path:
        return

    current_hash = hash_file(file_path)
    try:
        with open(hash_path, "r") as f:
            saved_hash = f.read().strip()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read hash file:\n{e}")
        return

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"Current Hash:\n{current_hash}\n")
    output_box.insert(tk.END, f"Saved Hash:\n{saved_hash}\n")

    if current_hash == saved_hash:
        output_box.insert(tk.END, "\n✅ Hashes match. File is intact.")
    else:
        output_box.insert(tk.END, "\n❌ Hashes do NOT match. File may have been altered!")

# GUI Setup
root = tk.Tk()
root.title("File Integrity Checker")
root.geometry("500x400")
root.resizable(False, False)

tk.Label(root, text="Select File:").pack(pady=5)
entry_file = tk.Entry(root, width=50)
entry_file.pack(pady=2)
tk.Button(root, text="Browse", command=select_file).pack()

tk.Button(root, text="Generate Hash", command=generate_hash).pack(pady=5)
tk.Button(root, text="Save Hash to File", command=save_hash).pack(pady=2)
tk.Button(root, text="Compare with Saved Hash", command=compare_hash).pack(pady=2)

output_box = scrolledtext.ScrolledText(root, height=10, width=60)
output_box.pack(pady=10)

root.mainloop()
