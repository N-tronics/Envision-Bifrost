# main.py
import Math_Utils
from Diffie_hellman import DiffieHellman

def main():
    print("--- Diffie-Hellman Key Exchange Simulation ---\n")

    # 1. Generate Public Parameters
    print("[System] Generating a 512-bit prime (this might take a few seconds)...")
    p = Math_Utils.generate_prime(512)
    g = 2 # 2 is a very common generator used in practice

    print(f"[System] Prime (p): {p}")
    print(f"[System] Generator (g): {g}\n")

    alice = DiffieHellman(p, g)
    bob = DiffieHellman(p, g)

    print("Alice generating her private and public keys...")
    alice.generate_keys()
    
    print("Bob generating his private and public keys...\n")
    bob.generate_keys()

    # 4. Exchange Public Keys & Compute Shared Secret
    print("Swapping public keys over the 'network'...")
    alice.compute_shared_secret(bob.get_public_key())
    bob.compute_shared_secret(alice.get_public_key())

    # 5. Verify the math works
    print("\n--- Final Results ---")
    print(f"Alice's Shared Secret: \n{alice.get_shared_secret()}")
    print(f"Bob's Shared Secret: \n{bob.get_shared_secret()}\n")

    if alice.get_shared_secret() == bob.get_shared_secret():
        print("SUCCESS! Both parties share the exact same secret key.")
    else:
        print("ERROR! The keys do not match.")

if __name__ == "__main__":
    main()