import tkinter as tk
import json, base64, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests

SERVER_URL = "http://127.0.0.1:5000/upload"

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + chr(pad_len) * pad_len

def encrypt_and_send():
    message = entry_msg.get()
    lat = float(entry_lat.get())
    lon = float(entry_lon.get())
    radius = float(entry_radius.get())

    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message).encode())

    payload = {
        "iv": base64.b64encode(iv).decode(),
        "key": base64.b64encode(key).decode(),
        "hmac_key": base64.b64encode(hmac_key).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "allowed_location": [lat, lon],
        "radius": radius
    }

    hmac_digest = hmac.new(hmac_key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).digest()
    payload["hmac"] = base64.b64encode(hmac_digest).decode()

    try:
        res = requests.post(SERVER_URL, json=payload)
        output.delete("1.0", tk.END)
        output.insert(tk.END, res.json()["message"])
    except Exception as e:
        output.delete("1.0", tk.END)
        output.insert(tk.END, str(e))

root = tk.Tk()
root.title("Sender - Secure Module Generator")

tk.Label(root, text="Message:").pack()
entry_msg = tk.Entry(root, width=50)
entry_msg.pack()

tk.Label(root, text="Allowed Latitude:").pack()
entry_lat = tk.Entry(root)
entry_lat.pack()

tk.Label(root, text="Allowed Longitude:").pack()
entry_lon = tk.Entry(root)
entry_lon.pack()

tk.Label(root, text="Allowed Radius (km):").pack()
entry_radius = tk.Entry(root)
entry_radius.pack()

tk.Button(root, text="Encrypt & Upload", command=encrypt_and_send).pack()
output = tk.Text(root, height=5, width=70)
output.pack()

root.mainloop()
