from setuptools import setup, find_packages
import os, pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="crypto_capsule",
    version="0.0.2",
    description="Just a small script based on python "
                "cryptography and electrum mnemonics "
                "to encapsulate your secrets.",
    long_description=long_description,
    url="https://github.com/vladiuz1/crypto-capsule",
    author="Vlad Smirnov",
    author_email="vlad@smirnov.com",
    packages=[
        'crypto_capsule',
    ],
    package_dir={'crypto_capsule': '.'},
    python_requires=">=3.8, <4",
    install_requires=[
        'click>=8.0.0',
        'cryptography>=37.0.4'
    ],
    data_files=[("wordlist", [
        "wordlist/english.txt"
    ])],
    entry_points={  # Optional
        "console_scripts": [
            "crypto-capsule=crypto_capsule.cli:cli",
        ],
    },
)
