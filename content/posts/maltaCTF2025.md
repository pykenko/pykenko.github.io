---
title: "Malta CTF 2025"
description: "Cool CTF"
tags: ["Cryptography"]
categories: ["Writeups"]
showTableOfContents: true
draft: false
---

# Title : Grammar Nazi
```
Just another standard RSA implementation.

Author : Neobeo
```

This challenge is very unique and a new one for me!

Here is the challenge provided source code

```python
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

m = f'The flag is {FLAG}'
c = pow(bytes_to_long(m.encode()), e, N)

# ERROR: Sentences should end with a period.
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

# All good now!
print(f'{N = }')
print(f'{c = }')

'''
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
'''
```

So basicly the challenge implements a standard rsa but the thing is, the challenge made the c turned into a c sum by adding 2 ciphertext into one.

Which means

```
c1 = M^e mod N
c2  = (256 * M + '.')^e mod N
csum = c1 + c2
```

as you can see the ct was combined, this makes its hard to solve because of the high degree.

We know that the challenge uses 

```
m^e + (256 * m + 46)^e - csum = 0 mod N
```

We can use mod p to help us solve this problem
```
m^e + (256 * m + 46)^e - csum = 0 mod P

Where
f(m) = m^e + (256 * m + 46)^e - csum = 0
```

We know the function uses mod p so we can use fermats little theorem

```
h(m) = m^p - m
g(m) = gcd(f(m), h(m))
g(m) = 0 mod p
```

So basicly we can take the gcd

g(m) will give us the roots in m mod p which satisfies f(m) = 0 mod p

Then we can solve this challenge by solving `g(m) + p * k = m`.

![Description of image](/images/maltaCTF2025.png)

{{< alert icon="check-circle" cardColor="#10b981" >}}
**Flag found:** `maltactf{Ferm4ts_littl3_polyn0mial_tr1ck}`
{{< /alert >}}