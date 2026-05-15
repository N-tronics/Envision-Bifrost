import secrets
import Math_Utils

P = 775145549137931
G = 23

def generate_keys():
    my_private_key = secrets.randbits(64) % (P - 2) + 2
    my_public_key = Math_Utils.mod_exp(G, my_private_key, P)
    return my_private_key, my_public_key

def compute_shared_secret(other_persons_public_key, my_private_key, modulus):
    final_shared_secret = Math_Utils.mod_exp(other_persons_public_key, my_private_key, modulus)
    return final_shared_secret