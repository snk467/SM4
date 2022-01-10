def long_to_bytes(n: int, length: int=0):
    if length == 0:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def bytes_to_long(x: bytes) -> int:
    return int.from_bytes(x, 'big')

def xor(*args: bytes):
    assert len(args) >= 2

    x = bytes_to_long(args[0])

    for y in args[1:]:
        x ^= bytes_to_long(y)

    return(long_to_bytes(x, 4))

def leftShift(x: bytes, shift: int) -> bytes:
        assert len(x) == 4
        n = bytes_to_long(x)
        N = 32
        n = ((n << shift) % (1 << N)) | (n >> (N - shift))
        return long_to_bytes(n, N//8)