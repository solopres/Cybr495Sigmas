import json
import tkinter as tk
from tkinter import ttk
import os

FILE = "open_ports.json"


def load_data():
    if not os.path.exists(FILE):
        return {"No data": ["Run scan first"]}

    try:
        with open(FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        return {"Error": [str(e)]}


def refresh():
    data = load_data()

    text.delete("1.0", tk.END)

    for ip, ports in data.items():
        text.insert(tk.END, f"{ip}\n")
        text.insert(tk.END, f"  Open Ports: {ports}\n\n")


# --- GUI ---
root = tk.Tk()
root.title("Open Ports Viewer")
root.geometry("500x400")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="both", expand=True)

text = tk.Text(frame)
text.pack(fill="both", expand=True)

btn = ttk.Button(frame, text="Refresh", command=refresh)
btn.pack(pady=5)

# Auto-load on start
refresh()

root.mainloop()