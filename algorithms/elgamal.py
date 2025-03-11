import random
import sympy
import numpy as np

def elgamal_generate_keys(key_size=32):
    print('Elgamal Ops : Generating Elgamal keys...')
    """Generate ElGamal key pair."""
    # Generate a large prime number p
    p = sympy.randprime(2 ** (key_size - 1), 2 ** key_size)

    # Find a primitive root g
    g = find_primitive_root(p)

    # Generate private key
    x = random.randint(2, p - 2)

    # Calculate public key y = g^x mod p
    y = pow(g, x, p)

    return {
        'public': {'p': p, 'g': g, 'y': y},
        'private': {'x': x}
    }


def find_primitive_root(p):
    """Find a primitive root modulo p."""
    if p == 2:
        return 1

    # Find prime factors of p-1
    factors = []
    phi = p - 1

    # Get the prime factors of phi
    for i in range(2, int(phi ** 0.5) + 1):
        if phi % i == 0:
            factors.append(i)
            while phi % i == 0:
                phi //= i

    if phi > 1:
        factors.append(phi)

    print('Elgamal Ops : Finding random primitive root')
    # Test random numbers until we find a primitive root
    while True:
        g = random.randint(2, p - 1)
        is_primitive = True

        for factor in factors:
            if pow(g, (p - 1) // factor, p) == 1:
                is_primitive = False
                break

        if is_primitive:
            return g


def elgamal_encrypt(public_key, message):
    """Encrypt a message using ElGamal."""
    p, g, y = public_key['p'], public_key['g'], public_key['y']

    # Choose random k
    k = random.randint(1, p - 2)

    # Calculate c1 = g^k mod p
    c1 = pow(g, k, p)

    # Calculate c2 = m * y^k mod p
    c2 = (message * pow(y, k, p)) % p

    return (c1, c2)


def elgamal_decrypt(public_key, private_key, ciphertext):
    """Decrypt a message using ElGamal."""
    p, x = public_key['p'], private_key['x']
    c1, c2 = ciphertext

    # Calculate s = c1^x mod p
    s = pow(c1, x, p)

    # Calculate s_inverse = s^(p-2) mod p (using Fermat's little theorem)
    s_inverse = pow(s, p - 2, p)

    # Calculate m = c2 * s_inverse mod p
    m = (c2 * s_inverse) % p

    return m

def euclidean_distance_homomorphic(public_key, enc_a, enc_b):
    """
    Calculate encrypted Euclidean distance using homomorphic properties.
    """
    p = public_key['p']
    squared_differences = []

    # For each coordinate
    for ea, eb in zip(enc_a, enc_b):
        diff = (ea[1] * pow(eb[1], p - 2, p)) % p  # Homomorphic subtraction (a/b mod p)
        squared = (diff * diff) % p  # not truly homomorphic
        squared_differences.append((ea[0], squared))

    # Sum the squared differences
    sum_squared = (0, 0)
    for i, sq in enumerate(squared_differences):
        if i == 0:
            sum_squared = sq
        else:
            sum_squared = (sum_squared[0], (sum_squared[1] + sq[1]) % p)

    return sum_squared