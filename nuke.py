import sys
import ctypes

# based on
# https://stackoverflow.com/a/58296046/13376175

# ok I quit this, not possible, cryptography is using bytes type for keeping
# secrets, and bytes type is in immutable memory. Hence we can't delete
# secrets from memory. Which is very sad tbh. The only way to get rid of
# secrets from memory in my use case:
#
# 1. Make sure your process does not use swap.
# 2. Turn off computer after each use.
#
# Otherwise no matter what i do secrets remain in memory and no way to
# wipe them from memory asaik. I had done a lot of gooooooglin and now testing
# too, to confirm that whatever you do you can't get rid of secrets stored
# as `bytes` object from memory with any amount of certainty at all.


def nuke(var):
    """
    This removes the variable contents from memory and derefereces it.

    :param var:
    :return:

    Only problem is, it doesn't work with `bytes`. And this is a show stopper.
    Most crypto libs work with bytes. I have tried many things, and you
    simply can't delete a `bytes` object from RAM in python.

    The only sure way to delete the object is by
    a). making sure your app is not using swap.
    b). reboot the system after use.
    """
    if isinstance(var, str):
        strlen = len(var)
        offset = sys.getsizeof(var) - strlen - 1
        ctypes.memset(id(var) + offset, 0, strlen)
        del var  # derefrencing the pointer.
    if isinstance(var, bytearray):
        blen = len(var)
        mv = memoryview(var)
        for i in range(blen):
            mv[i]=0
        del var
