from .cmac import CMAC
from .hmac import HMAC


def constant_time_equal(a: bytes, b: bytes) -> bool:
    # сравнение без раннего выхода: время не выдаёт, сколько первых байт MAC совпало
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
