#!/usr/bin/env python
#
#
# Simplified version of https://github.com/spesmilo/electrum/blob/master/electrum/mnemonic.py
#
# This is needed in order to compact saving of electrum mnemonic phrases since
# they are not bip39 compatible.
#
# At the moment Electrum mnemonic phrases of up to 4.1.5 are supported. These are all 24
# words in length asaik.
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import math
import hashlib
import unicodedata
import string
import secrets
import hmac
from typing import Sequence, Dict, Tuple, Union
from types import MappingProxyType
from unicodedata import normalize

pkg_dir = os.path.split(os.path.realpath(__file__))[0]

wordlist_location = os.path.join(sys.prefix, 'wordlist')
if not os.path.isdir(wordlist_location):
    wordlist_location = os.path.join(*__path__, 'wordlist')

bfh = bytes.fromhex

ELECTRUM_VERSION = '4.1.5'  # version of the client package
APK_VERSION = '4.1.5.0'  # read by buildozer.spec

PROTOCOL_VERSION = '1.4'  # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX = '01'  # Standard wallet
SEED_PREFIX_SW = '100'  # Segwit wallet
SEED_PREFIX_2FA = '101'  # Two-factor authentication
SEED_PREFIX_2FA_SW = '102'  # Two-factor auth, using segwit


def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
    elif seed_type == '2fa':
        return SEED_PREFIX_2FA
    elif seed_type == '2fa_segwit':
        return SEED_PREFIX_2FA_SW
    raise Exception(f"unknown seed_type: {seed_type}")


def randrange(bound: int) -> int:
    """Return a random integer k such that 1 <= k < bound, uniformly
    distributed across that range."""
    # secrets.randbelow(bound) returns a random int: 0 <= r < bound,
    # hence transformations:
    return secrets.randbelow(bound - 1) + 1


def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object
    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()


def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()


# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F, 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]


def is_CJK(c):
    n = ord(c)
    for imin, imax, name in CJK_INTERVALS:
        if n >= imin and n <= imax: return True
    return False


def normalize_text(seed: str) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i]
                     for i in range(len(seed))
                     if not (seed[i] in string.whitespace and is_CJK(seed[i - 1]) and is_CJK(seed[i + 1]))])
    return seed


_WORDLIST_CACHE = {}  # type: Dict[str, Wordlist]


class Wordlist(tuple):

    def __init__(self, words: Sequence[str]):
        super().__init__()
        index_from_word = {w: i for i, w in enumerate(words)}
        self._index_from_word = MappingProxyType(index_from_word)  # no mutation

    def index(self, word, start=None, stop=None) -> int:
        try:
            return self._index_from_word[word]
        except KeyError as e:
            raise ValueError from e

    def __contains__(self, word) -> bool:
        try:
            self.index(word)
        except ValueError:
            return False
        else:
            return True

    @classmethod
    def from_file(cls, filename) -> 'Wordlist':
        path = os.path.join(wordlist_location, filename)
        if path not in _WORDLIST_CACHE:
            with open(path, 'r', encoding='utf-8') as f:
                s = f.read().strip()
            s = unicodedata.normalize('NFKD', s)
            lines = s.split('\n')
            words = []
            for line in lines:
                line = line.split('#')[0]
                line = line.strip(' \r')
                assert ' ' not in line
                if line:
                    words.append(line)

            _WORDLIST_CACHE[path] = Wordlist(words)
        return _WORDLIST_CACHE[path]


def to_bytes(something, encoding='utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def bip39_is_checksum_valid(
        mnemonic: str,
        *,
        wordlist: Wordlist = None,
) -> Tuple[bool, bool]:
    """Test checksum of bip39 mnemonic assuming English wordlist.
    Returns tuple (is_checksum_valid, is_wordlist_valid)
    """
    words = [normalize('NFKD', word) for word in mnemonic.split()]
    words_len = len(words)
    if wordlist is None:
        wordlist = Wordlist.from_file("english.txt")
    n = len(wordlist)
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False
        i = i * n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    checksum_length = 11 * words_len // 33  # num bits
    entropy_length = 32 * checksum_length  # num bits
    entropy = i >> checksum_length
    checksum = i % 2 ** checksum_length
    entropy_bytes = int.to_bytes(entropy, length=entropy_length // 8, byteorder="big")
    hashed = int.from_bytes(sha256(entropy_bytes), byteorder="big")
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True


filenames = {
    'en': 'english.txt',
    'es': 'spanish.txt',
    'ja': 'japanese.txt',
    'pt': 'portuguese.txt',
    'zh': 'chinese_simplified.txt'
}


class Mnemonic():
    # Seed derivation does not follow BIP39
    # Mnemonic phrase uses a hash based checksum, instead of a wordlist-dependent checksum

    def __init__(self, lang=None):
        lang = lang or 'en'
        filename = filenames.get(lang[0:2], 'english.txt')
        self.wordlist = Wordlist.from_file(filename)

    @classmethod
    def mnemonic_to_seed(self, mnemonic, passphrase) -> bytes:
        PBKDF2_ROUNDS = 2048
        mnemonic = normalize_text(mnemonic)
        passphrase = passphrase or ''
        passphrase = normalize_text(passphrase)
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'electrum' + passphrase.encode('utf-8'),
                                   iterations=PBKDF2_ROUNDS)

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i % n
            i = i // n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def get_suggestions(self, prefix):
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    def mnemonic_decode(self, seed):
        n = len(self.wordlist)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = self.wordlist.index(w)
            i = i * n + k
        return i

    def make_seed(self, *, seed_type=None, num_bits=None) -> str:
        if seed_type is None:
            seed_type = 'segwit'
        if num_bits is None:
            num_bits = 132
        prefix = seed_prefix(seed_type)
        # increase num_bits in order to obtain a uniform distribution for the last word
        bpw = math.log(len(self.wordlist), 2)
        num_bits = int(math.ceil(num_bits / bpw) * bpw)
        entropy = 1
        while entropy < pow(2, num_bits - bpw):
            # try again if seed would not contain enough words
            entropy = randrange(pow(2, num_bits))
        nonce = 0
        while True:
            nonce += 1
            i = entropy + nonce
            seed = self.mnemonic_encode(i)
            if i != self.mnemonic_decode(seed):
                raise Exception('Cannot extract same entropy from mnemonic!')
            # Make sure the mnemonic we generate is not also a valid bip39 seed
            # by accident. Note that this test has not always been done historically,
            # so it cannot be relied upon.
            if bip39_is_checksum_valid(seed, wordlist=self.wordlist) == (True, True):
                continue
            if is_new_seed(seed, prefix):
                break
        return seed


def is_new_seed(x: str, prefix=SEED_PREFIX) -> bool:
    x = normalize_text(x)
    s = bh2u(hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512))
    return s.startswith(prefix)

def seed_type(x: str) -> str:
    num_words = len(x.split())
    if is_new_seed(x, SEED_PREFIX):
        return 'standard'
    elif is_new_seed(x, SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, SEED_PREFIX_2FA) and (num_words == 12 or num_words >= 20):
        # Note: in Electrum 2.7, there was a breaking change in key derivation
        #       for this seed type. Unfortunately the seed version/prefix was reused,
        #       and now we can only distinguish them based on number of words. :(
        return '2fa'
    elif is_new_seed(x, SEED_PREFIX_2FA_SW):
        return '2fa_segwit'
    return ''


def is_seed(x: str) -> bool:
    return bool(seed_type(x))


def is_any_2fa_seed_type(seed_type: str) -> bool:
    return seed_type in ['2fa', '2fa_segwit']
