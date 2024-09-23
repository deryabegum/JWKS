import unittest
import json
import time
from app import app, generate_rsa_keypair, keys
import jwt

class TestJWKS(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        generate_rsa_keypair()

    def test_jwks_endpoint(self):
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        self.assertEqual(len(data['keys']), 1)
        self.assertIn('kid', data['keys'][0])

    def test_auth_active_key(self):
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        decoded_token = jwt.decode(data['token'], options={"verify_signature": False})
        self.assertEqual(decoded_token['sub'], "1234567890")

    def test_auth_expired_key(self):
        keys[0]['expiry'] = time.time() - 1
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        decoded_token = jwt.decode(data['token'], options={"verify_signature": False})
        self.assertEqual(decoded_token['sub'], "1234567890")

if __name__ == '__main__':
    unittest.main()

