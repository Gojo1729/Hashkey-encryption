import random


class DiffieHellman:
    def _init_(self, prime_bits=30, generator=2):
        self.prime_bits = prime_bits
        self.generator = generator

    def generate_keypair(self, prime_number):
        self.prime = prime_number  # Fix: Assign the prime_number to self.prime
        self.private_key = random.randint(2, self.prime - 2)
        self.public_key = pow(self.generator, self.private_key, self.prime)
        # Public key = generator^privatekey mod prime
        return self.private_key, self.public_key, self.prime

    def calculate_shared_secret(self, public_key, private_key,prime):
        shared_secret = pow(public_key, private_key, prime)
        # Shared Secret = public key ^ private key mod prime
        return shared_secret
    



    ###BRO ADDED IMPLEMENTATION SO IT WILL BE EASY FOR YOU 

alice = DiffieHellman()
bob = DiffieHellman()

# Choose a prime number
prime_number = 10000000007

# Generate key pairs for Alice and Bob
private_key_A, public_key_A, prime_A = alice.generate_keypair(prime_number)
private_key_B, public_key_B, prime_B = bob.generate_keypair(prime_number)

# Print the results
print("Alice's private key:", private_key_A)
print("Alice's public key:", public_key_A)
print(prime_A)
print("\nBob's private key:", private_key_B)
print("Bob's public key:", public_key_B)
print(prime_B)
# Calculate shared secrets
shared_secret_A = alice.calculate_shared_secret(public_key_B)
shared_secret_B = bob.calculate_shared_secret(public_key_A)

# Print the shared secrets
print("\nShared secret for Alice:", shared_secret_A)
print("Shared secret for Bob:", shared_secret_B)