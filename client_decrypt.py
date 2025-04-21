import tkinter as tk
import requests
import geocoder

SERVER_URL = "http://127.0.0.1:5000/decrypt"

def decrypt():
    g = geocoder.ip('me')
    user_loc = g.latlng

    try:
        response = requests.post(SERVER_URL, json={"user_location": user_loc})
        if response.status_code == 200:
            output_label.config(text="Decrypted: " + response.json()['decrypted'])
        else:
            output_label.config(text="Error: " + response.json().get('error', 'Unknown error'))
    except Exception as e:
        output_label.config(text="Exception: " + str(e))

# GUI Setup
root = tk.Tk()
root.title("Receiver - Decrypt with Location")
root.geometry("600x300")  # Set window size

# Heading
heading = tk.Label(root, text="Location-Based Decryption", font=("Helvetica", 18, "bold"))
heading.pack(pady=20)

# Decrypt Button
decrypt_button = tk.Button(root, text="Request & Decrypt Message", command=decrypt, font=("Helvetica", 14), width=30)
decrypt_button.pack(pady=10)

# Output Label
output_label = tk.Label(root, text="", wraplength=500, font=("Helvetica", 12), justify="center")
output_label.pack(pady=20)

root.mainloop()
