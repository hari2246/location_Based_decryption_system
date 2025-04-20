# This file runs your GUI and connects to the server
import tkinter as tk
import requests
import geocoder

SERVER_URL = "http://127.0.0.1:5000/decrypt"

def decrypt():
    module_b64 = input_module.get("1.0", tk.END).strip()
    g = geocoder.ip('me')
    user_loc = g.latlng

    try:
        response = requests.post(SERVER_URL, json={
            "module": module_b64,
            "user_location": user_loc
        })

        if response.status_code == 200:
            output_label.config(text="Decrypted: " + response.json()['decrypted'])
        else:
            output_label.config(text="Error: " + response.json()['error'])
    except Exception as e:
        output_label.config(text="Exception: " + str(e))

root = tk.Tk()
root.title("Secure Decryption with Location Verification")

tk.Label(root, text="Paste Encrypted Module:").pack()
input_module = tk.Text(root, height=12, width=70)
input_module.pack()

tk.Button(root, text="Attempt Decryption", command=decrypt).pack()
output_label = tk.Label(root, text="")
output_label.pack()

root.mainloop()
