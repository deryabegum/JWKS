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
        # Get the current valid 'kid' from the JWKS
        jwks_response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        jwks_keys = jwks_response.json()['keys']
        current_kid = jwks_keys[0]['kid']  # Assume first valid key for test
        
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
        
        # Check if the 'kid' in the JWT matches the 'kid' served by JWKS
        self.assertEqual(header['kid'], current_kid)

    def test_expired_auth_endpoint(self):
        # Send a POST request to the /auth endpoint with 'expired=true'
        response = requests.post(f"{BASE_URL}/auth?expired=true")
        
        # Check the status code
        self.assertEqual(response.status_code, 200)
        
        # Check if the response contains a 'token' field
        data = response.json()
        self.assertIn("token", data)
        
        # Verify the token
        token = data['token']
        header = jwt.get_unverified_header(token)
        
        # Expired tokens should still have a 'kid', ensure it exists
        self.assertIn('kid', header)

if __name__ == '__main__':
    unittest.main()
