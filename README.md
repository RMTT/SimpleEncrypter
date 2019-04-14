# Simple Encrypter
## Introduce
A simple encrypter that uses several symmetrical cipher.
## Usage
```python
from encrypt import Encrypter
encrypet = Encrypter()
text = b"RC2 has a fixed data block size of 8 bytes. Length of its keys can vary from 8 to 128 bits. One particular property of RC2 is that the actual cryptographic strength of the key (effective key length) can be reduced via a parameter."
id, ct = encrypet.encrypt(text)
print(ct)
print(encrypet.decrypt(ct, id))
```