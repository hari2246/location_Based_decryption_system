# This file ONLY runs the Flask server. No GUI here.
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64, json, hmac, hashlib
from geopy.distance import geodesic

app = Flask(__name__)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        module_b64 = data.get("module")
        user_location = data.get("user_location")

        decoded = base64.b64decode(module_b64).decode()
        module = json.loads(decoded)

        hmac_key = base64.b64decode(module["hmac_key"])
        provided_hmac = base64.b64decode(module["hmac"])

        module_copy = module.copy()
        del module_copy["hmac"]

        recalculated_hmac = hmac.new(hmac_key, json.dumps(module_copy, sort_keys=True).encode(), hashlib.sha256).digest()

        if not hmac.compare_digest(provided_hmac, recalculated_hmac):
            return jsonify({"error": "Integrity check failed!"}), 400

        allowed_location = tuple(module["allowed_location"])
        radius_km = module["radius"]
        distance = geodesic(user_location, allowed_location).km

        if distance > radius_km:
            return jsonify({"error": "Access Denied: Outside allowed location"}), 403

        key = base64.b64decode(module["key"])
        iv = base64.b64decode(module["iv"])
        ciphertext = base64.b64decode(module["ciphertext"])

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext)).decode()

        return jsonify({"decrypted": plaintext})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
