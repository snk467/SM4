from SM4 import *
from termcolor import colored
from tqdm import tqdm

def printFAIL():
    print("[", colored('FAIL', 'red'), "]", end=' ')

def printOK():
    print("[", colored('OK', 'green'), "]", end=' ')

#region Test #1 - Encrypt plaintext with key once

#region Test data
plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
expectedCiphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")

expectedRoundKeys = []
expectedRoundKeys.append("f12186f9")
expectedRoundKeys.append("41662b61")
expectedRoundKeys.append("5a6ab19a")
expectedRoundKeys.append("7ba92077")
expectedRoundKeys.append("367360f4")
expectedRoundKeys.append("776a0c61")
expectedRoundKeys.append("b6bb89b3")
expectedRoundKeys.append("24763151")
expectedRoundKeys.append("a520307c")
expectedRoundKeys.append("b7584dbd")
expectedRoundKeys.append("c30753ed")
expectedRoundKeys.append("7ee55b57")
expectedRoundKeys.append("6988608c")
expectedRoundKeys.append("30d895b7")
expectedRoundKeys.append("44ba14af")
expectedRoundKeys.append("104495a1")
expectedRoundKeys.append("d120b428")
expectedRoundKeys.append("73b55fa3")
expectedRoundKeys.append("cc874966")
expectedRoundKeys.append("92244439")
expectedRoundKeys.append("e89e641f")
expectedRoundKeys.append("98ca015a")
expectedRoundKeys.append("c7159060")
expectedRoundKeys.append("99e1fd2e")
expectedRoundKeys.append("b79bd80c")
expectedRoundKeys.append("1d2115b0")
expectedRoundKeys.append("0e228aeb")
expectedRoundKeys.append("f1780c81")
expectedRoundKeys.append("428d3654")
expectedRoundKeys.append("62293496")
expectedRoundKeys.append("01cf72e5")
expectedRoundKeys.append("9124a012")

expectedRoundOutputs = []
expectedRoundOutputs.append("27fad345")
expectedRoundOutputs.append("a18b4cb2")
expectedRoundOutputs.append("11c1e22a")
expectedRoundOutputs.append("cc13e2ee")
expectedRoundOutputs.append("f87c5bd5")
expectedRoundOutputs.append("33220757")
expectedRoundOutputs.append("77f4c297")
expectedRoundOutputs.append("7a96f2eb")
expectedRoundOutputs.append("27dac07f")
expectedRoundOutputs.append("42dd0f19")
expectedRoundOutputs.append("b8a5da02")
expectedRoundOutputs.append("907127fa")
expectedRoundOutputs.append("8b952b83")
expectedRoundOutputs.append("d42b7c59")
expectedRoundOutputs.append("2ffc5831")
expectedRoundOutputs.append("f69e6888")
expectedRoundOutputs.append("af2432c4")
expectedRoundOutputs.append("ed1ec85e")
expectedRoundOutputs.append("55a3ba22")
expectedRoundOutputs.append("124b18aa")
expectedRoundOutputs.append("6ae7725f")
expectedRoundOutputs.append("f4cba1f9")
expectedRoundOutputs.append("1dcdfa10")
expectedRoundOutputs.append("2ff60603")
expectedRoundOutputs.append("eff24fdc")
expectedRoundOutputs.append("6fe46b75")
expectedRoundOutputs.append("893450ad")
expectedRoundOutputs.append("7b938f4c")
expectedRoundOutputs.append("536e4246")
expectedRoundOutputs.append("86b3e94f")
expectedRoundOutputs.append("d206965e")
expectedRoundOutputs.append("681edf34")

#endregion

cipher = SM4(key)

roundKeys = [key.hex() for key in cipher.getRoundKeys()]

# Test round keys
assert roundKeys == expectedRoundKeys, "roundKeys are not equal expectedRoundKeys"

ciphertext = cipher.encrypt(plaintext)

roundOutputs = [roundOutput.hex() for roundOutput in cipher.getRecentOutputs()]

# Test round outputs
assert roundOutputs == expectedRoundOutputs, "roundsOutputs are not equal expectedRoundsOutputs"

# Test ciphertext 
if ciphertext == expectedCiphertext:
    printOK()
else:
    printFAIL()

print("Encrypt plaintext with key once.", "Expected result: ", expectedCiphertext.hex(), "Result:", ciphertext.hex())

#endregion

#region Test #2 - Decrypt ciphertext with key once

# Test data
ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
expectedPlaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

cipher = SM4(key)

plaintext = cipher.decrypt(ciphertext)

# Test plaintext 
if plaintext == expectedPlaintext:
    printOK()
else:
    printFAIL()

print("Decrypt ciphertext with key once.", "Expected result: ", expectedPlaintext.hex(), "Result:", plaintext.hex())

#endregion

#region Test #3 - 1000000 iterations encryption

# Test data
plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
expectedCiphertext = bytes.fromhex("595298c7c6fd271f0402f804c33d3f66")

cipher = SM4(key)

ciphertext = plaintext
for _ in tqdm(range(0,1000000), leave=False):
    ciphertext = cipher.encrypt(ciphertext)

# Test ciphertext 
if ciphertext == expectedCiphertext:
    printOK()
else:
    printFAIL()

print("1000000 iterations encryption.", "Expected result: ", expectedCiphertext.hex(), "Result:", ciphertext.hex())

#endregion

#region Test #4 - 1000000 iterations decryption

# Test data
ciphertext = bytes.fromhex("595298c7c6fd271f0402f804c33d3f66")
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
expectedPlaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

cipher = SM4(key)

for _ in tqdm(range(0,1000000), leave=False):
    ciphertext = cipher.decrypt(ciphertext)

plaintext = ciphertext

# Test ciphertext 
if plaintext == expectedPlaintext:
    printOK()
else:
    printFAIL()

print("1000000 iterations decryption.", "Expected result: ", expectedPlaintext.hex(), "Result:", plaintext.hex())

#endregion