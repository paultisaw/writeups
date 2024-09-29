# Really Secure Algorithm (Crypto)
Polygl0ts friday meeting 1, 27.09.2024
## Introduction
> You can try to decrypt our flag but good luck because we used a really secure algorithm to encrypt it.
> Flag format: EPFL{...}

We are given the following two files:

`encode.py`
```python
from binascii import hexlify

e = 5
n = 6218180873

with open('flag.txt', 'r') as f:
    flag = f.read().strip()

flag = int(hexlify(flag.encode()), 16) 

enc = 0 
while flag > 0:
    enc = enc * n + pow(flag % n, e, n)
    flag //= n

with open('flag.enc', 'w') as f:
    f.write(str(enc))
    
```
`flag.enc`
```
78431868284687617744319415906536563690186491306203835758640568840973349420889760911367278456379958
```

The first one is the script that was used to encrypt the flag, and the second is the flag we want to decryt as an int.

## Vulnerability

We recognize [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) with the `e` and `n` variables, as well as the call to `pow`.

We then notice that the `n` variable is relatively low, which means we can potentially recover the prime factors used to compute it.

## Exploitation
Using [factordb](http://www.factordb.com/), we find `p = 72089` and `q = 86257`. 
With this we can compute the following number ($\varphi$ is [euler's totient function](https://en.wikipedia.org/wiki/Euler's_totient_function).):

$$\varphi(n) = (p-1) * (q-1)$$

This will allow us to compute the number `d`, defined such that $ed \equiv 1 \mod{\varphi(n)}$:
$$d = e^{-1} \mod{\varphi(n)}$$

Here is how to do it in Python:
```python
from binascii import hexlify
from sympy import mod_inverse


e = 5
n = 6218180873

p = 72089
q = 86257

phi_n = (p - 1) * (q - 1)
d = mod_inverse(e, phi_n)
```
We can test that our `d` is correct by encrypting then decrypting some dummy value

```python
value = 1234
test = pow(value, e, n)
decrypt = pow(test, d, n)
assert value == decrypt 
```

We are now able to decrypt the flag, but we have a final issue to address, 
because as we see in the provided script, there is some chunking going on.
Since the flag representation is bigger than `n`, if we would just encrypt it as is we would lose information.
So we need to decrypt it chunk by chunk.

You can read the collapsed section below if you are interested in the small bit of math going on (which took me some time to grasp) ;)
<details>

<summary>Details</summary>

The flag can be written in a base $n$ representation:

$$f = F_0 + F_1*n + F_2*n^2 + ... + F_k * n^k$$

We will be encrypting one digit after the other, but for this we need a way to extract each digit. 
We can do the following:
$$F_0 = f\mod{n}$$

Then to get $F_1$ we take the integer division of our $f$ by $n$, followed by a new modulo $n$ and so on.

Once we have the digits, we encrypt them using the RSA formula:
$$C_0 = F_0^e \mod{n}$$
$$...$$
$$C_k = F_k^e \mod{n}$$

And finally we add them up again to obtain our ciphertext:

$$C = C_0 + C_1*n + C_2*n^2 + ... + C_k * n^k$$

So to decrypt it we need to do the same operations but decrypting each digit instead of encrypting.

>Note that this is not a standard mode of operation of RSA because
>it is usually used in combination with a block cipher to do the heavy lifting, 
>and the symmetric key is typically much smaller than $n$.
</details>

Finally, we decrypt the flag with the following snippet:
```python
with open('flag.enc', 'r') as f:
    c = int(f.read().strip())

flag = 0

while c > 0:
    flag = flag * n + pow(c % n, d, n)
    c //= n

print(str(flag.to_bytes(64, byteorder='big'), 'utf-8'))
```

**Flag:** `EPFL{small_numbers_make_rsa_go_nooooooo}`

And so we get the flag ! :D