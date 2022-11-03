import click
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_wrap, aes_key_unwrap_with_padding
from . import Key, Salt, Capsule

@click.group()
def cli():
    pass

@cli.command()
def test():
    print(Key.generate().encrypt(bytes(Key.generate())))


@cli.command()
def test2():
    key = Key.from_mnemonic('saddle bunker walnut equal solar undo vicious puzzle inquiry income drive afraid detect '
                            'runway explain medal avoid stairs pencil equip dinosaur gadget pistol above')
    capsule = Capsule.create(key, b'Hello world')
    print(capsule.to_mnemonic())
    print(capsule.cipherText().hex())
    print(capsule.id())
    print(capsule.open(key))
    capsule = capsule.from_mnemonic('mobile domain display test smile yard tank soldier duty radar mimic hidden blush '
                                    'erosion curve van faculty razor cash march boss animal hello poverty route auto '
                                    'gown ghost vacant salmon aisle indoor sister ice final produce blanket trouble '
                                    'age flip help train erode aim direct mountain such vault history account abandon '
                                    'abandon abandon margin gift expand author')
    print(capsule.cipherText().hex())
    print(capsule.id())

@cli.command()
@click.argument('mnemonic', nargs=1, type=click.STRING)
def key_from_mnemonic(mnemonic):
    print(Key.from_mnemonic(mnemonic))
    """
    test key from mnemonic

    :param mnemonic:
    :return:
    """