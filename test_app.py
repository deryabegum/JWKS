import unittest
import requests
import jwt

# The base URL for your JWKS server
BASE_URL = "http://127.0.0.1:8080"

class TestJWKS(unittest.TestCase):
    
    def test_jwks_endpoint(self):
        # Send a GET request to the JWKS endpoint
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        
        # Check the status code
        self.assertEqual(response.status_code, 200)
        
        # Check if the response contains a valid 'keys' field
        data = response.json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0)

    def test_auth_endpoint(self):
        # Send a POST request to the /auth endpoint to get a JWT
        response = requests.post(f"{BASE_URL}/auth")
        
        # Check the status code
        self.assertEqual(response.status_code, 200)
        
        # Check if the response contains a 'token' field
        data = response.json()
        self.assertIn("token", data)
        
        # Verify the token
        token = data['token']
        header = jwt.get_unverified_header(token)
        
        # Check if the 'kid' in the header matches the one served by the JWKS
        self.assertEqual(header['kid'], '1')

if __name__ == '__main__':
    unittest.main()

