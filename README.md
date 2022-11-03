A convenience module for symmetric cryptography based on cryptography.fernet

Fernet library is in turn based on AES (128 bit) cryptography. More on that here:
https://cryptography.io/en/latest/fernet/

# Install

Reqruires:

 * `Python >= 3.8`

Run install:

```bash
pip3 install crypto_capsule
```

# Get started

```python
from crypto_capsule import Key, Capsule

# derive a key from password
key = Key.from_password(b'Test me')

# encapsulate your secret
capsule = Capsule.create(key, b'This is a secret message')
print(capsule.open(key))
```

# Use with mnemonics

```python
from crypto_capsule import Key, Capsule

# create a new key (more secure than password)
key = Key.generate()

# print the key as a mnemonic phrase
print(key.to_mnemonic())


# encapsulate your secret
capsule = Capsule.create(key, b'This is a secret message')

# see what the capsule looks like as a mnemonic phrase
print(capsule.to_mnemonic())

# open the capsule with the key
print(capsule.open(key))
```


# TODO

A client to manipulate files. A template for that is done in `cli.py`, and installed as `crypt-capsule`
command. May be someone wants to extend that?

# License

[MIT License](LICENSE)

# Author

vlad @ smirnov.com