import secrets
import random

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp>0:
        if(exp%2==1):
            result = (result*base)%mod
        exp = exp//2
        base = (base*base)%mod
    return result

def random_odd_integer(bitlength):
    num = secrets.randbits(bitlength)
    num = num|1
    return num

def isPrime(n,k=40):
    if(n<=1):
        return False
    if(n<=3):
        return True
    if(n%2==0):
        return False
    r = 0
    oddpart= n-1
    while(oddpart%2==0):
        oddpart = oddpart//2
        r = r+1
    for i in range(k):
        a = random.randint(2,n-2)
        x = mod_exp(a, oddpart, n)
        if(x==1 or x==n-1): #initial check
            continue
        passed = False
        temp_d = oddpart
        while temp_d != n - 1:
            x = (x * x) % n
            temp_d = temp_d * 2

            if x == 1:
                return False
            if x == n - 1:
                passed = True
                break
        
        if passed == False:
            return False
            
    return True

def generate_prime(bit_length):
    candidate = 0
    prime_found = False
    while prime_found == False:
        candidate = random_odd_integer(bit_length)
        if isPrime(candidate)==True:
            prime_found = True
    return candidate