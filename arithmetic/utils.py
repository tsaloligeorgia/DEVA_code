from sympy.ntheory import factorint

def totient(n):
    totient = n
    for factor in factorint(n):
        totient -= totient // factor
    return totient
