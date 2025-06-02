import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2
import re
import hashlib
import os
from datetime import datetime

base_dir = r"C:\Users\Harry Binu\OneDrive\Desktop\new"

blacklist_files = [
    os.path.join(base_dir, "blacklist.txt"),
    os.path.join(base_dir, "DB2.txt"),
    os.path.join(base_dir, "threatfox.abuse.ch.txt")
]

def load_blacklists(paths):
    domains = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        if '\t' in line:
                            parts = line.split()
                            if len(parts) > 1:
                                domains.add(parts[1])
                        elif line.startswith("http"):
                            matches = re.findall(r'https?://(?:www\.)?([^/\s]+)', line)
                            if matches:
                                domains.add(matches[0])
                        else:
                            domains.add(line)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load {path}: {e}")
    return domains

def extract_domains(pdf_path):
    try:
        reader = PyPDF2.PdfReader(pdf_path)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return set(re.findall(r'https?://(?:www\.)?([^/\s]+)', text))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read PDF: {e}")
        return set()

def detect_embedded_javascript(pdf_path):
    suspicious_markers = []
    try:
        with open(pdf_path, "rb") as f:
            content = f.read().decode("latin1", errors="ignore")
            if re.search(r"/(JavaScript|JS)\b", content):
                suspicious_markers.append("/JavaScript or /JS object found")
            if re.search(r"/AA\b", content):
                suspicious_markers.append("/AA (Additional Action) object found")
            if re.search(r"/OpenAction\b", content):
                suspicious_markers.append("/OpenAction (Auto-run on open) found")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan for embedded JavaScript: {e}")
    return suspicious_markers

def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def save_log(file_path, detected_domains, all_domains, js_warnings):
    log_dir = os.path.join(base_dir, "scan_reports")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"File: {file_path}\n")
        f.write(f"Scanned at: {timestamp}\n")
        f.write(f"SHA-256: {compute_sha256(file_path)}\n\n")

        f.write("Malicious domains detected:\n")
        for d in detected_domains:
            f.write(f" - {d}\n")

        f.write("\nAll extracted domains:\n")
        for d in all_domains:
            f.write(f" * {d}\n")

        f.write("\nEmbedded JavaScript or suspicious objects:\n")
        for js in js_warnings:
            f.write(f" ! {js}\n")
    return log_file

def scan_pdf():
    file_path = filedialog.askopenfilename(
        title="Select PDF to scan",
        initialdir=base_dir,
        filetypes=[("PDF files", "*.pdf")]
    )
    if not file_path:
        return

    blacklist = load_blacklists(blacklist_files)
    extracted_domains = extract_domains(file_path)
    matched_domains = extracted_domains.intersection(blacklist)
    js_warnings = detect_embedded_javascript(file_path)

    log_file = save_log(file_path, matched_domains, extracted_domains, js_warnings)

    if matched_domains or js_warnings:
        msg = ""
        if matched_domains:
            msg += f"Malicious domains:\n{', '.join(matched_domains)}\n"
        if js_warnings:
            msg += "\nSuspicious JavaScript behavior detected:\n" + "\n".join(js_warnings)
        msg += f"\n\nLog saved at:\n{log_file}"
        messagebox.showwarning("Threats Detected", msg)
    else:
        messagebox.showinfo("Scan Complete", f"No malicious domains or JavaScript found.\n\nLog saved at:\n{log_file}")

root = tk.Tk()
root.title("Offline PDF Malware Scanner")

canvas = tk.Canvas(root, width=400, height=200)
canvas.pack()

label = tk.Label(root, text="Select a PDF file to scan for malicious links and JavaScript", font=("Arial", 12))
canvas.create_window(200, 50, window=label)

scan_button = tk.Button(root, text="Scan PDF", command=scan_pdf, width=20, height=2, bg="darkred", fg="white")
canvas.create_window(200, 120, window=scan_button)

root.mainloop()
