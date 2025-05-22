import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Could not read file:\n{e}")
        return None

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def generate_hash():
    file_path = entry_file.get().strip()
    if not file_path:
        messagebox.showerror("Missing File", "Please select a file.")
        return

    hash_result = compute_hash(file_path)
    if hash_result:
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, f"SHA-256 Hash:\n{hash_result}")
        btn_save.config(state="normal")

def save_hash():
    hash_text = output_box.get("1.0", tk.END).strip()
    if not hash_text:
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if save_path:
        with open(save_path, "w") as f:
            f.write(hash_text)
        messagebox.showinfo("Saved", "Hash saved successfully!")

# --- GUI Setup ---
root = tk.Tk()
root.title("File Integrity Checker")
root.geometry("500x350")
root.resizable(False, False)

tk.Label(root, text="Select File:").pack(pady=5)
entry_file = tk.Entry(root, width=50)
entry_file.pack(padx=10)
tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

tk.Button(root, text="Generate Hash", command=generate_hash).pack(pady=10)

output_box = scrolledtext.ScrolledText(root, height=6, width=60)
output_box.pack(padx=10, pady=10)

btn_save = tk.Button(root, text="Save Hash", command=save_hash, state="disabled")
btn_save.pack(pady=5)

root.mainloop()
