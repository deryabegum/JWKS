from flask import Flask, jsonify, request
import time 
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Store keys
keys = []

# Generate an RSA key pair and store it with an expiry
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    keys.append({
        "private_key": private_key,
        "public_key": public_key,
        "kid": str(len(keys) + 1),  # Incrementing Key ID
        "expiry": time.time() + 3600  # Keys expire in 1 hour
    })

# Generate a JWK-compliant dictionary from an RSA public key
def jwk_from_public_key(public_key, kid):
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": format(n, 'x'),
        "e": format(e, 'x')
    }

# JWKS endpoint to serve active keys
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    active_keys = [jwk_from_public_key(key['public_key'], key['kid']) for key in keys if time.time() < key['expiry']]
    return jsonify({"keys": active_keys})

# /auth endpoint to issue a JWT
@app.route('/auth', methods=['POST'])
def auth():
    if not keys:
        return jsonify({"error": "No keys available"}), 500
    private_key = keys[0]['private_key']
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time()
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "1"})
    return jsonify({"token": token})

if __name__ == '__main__':
    # Generate an initial RSA keypair
    generate_rsa_keypair()

    # Start Flask server
    print("Starting JWKS Server...")
    app.run(port=8080, debug=True)

