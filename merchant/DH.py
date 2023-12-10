import random


class DiffieHellman:
    def generate_keypair(self, prime_number):
        self.prime = prime_number  # Fix: Assign the prime_number to self.prime
        self.private_key = random.randint(2, self.prime - 2)
        self.public_key = pow(generator, self.private_key, self.prime)
        # Public key = generator^privatekey mod prime
        return self.private_key, self.public_key, self.prime

    def calculate_shared_secret(self, public_key, private_key, prime):
        shared_secret = pow(public_key, private_key, prime)
        # Shared Secret = public key ^ private key mod prime
        return shared_secret


generator = 2
