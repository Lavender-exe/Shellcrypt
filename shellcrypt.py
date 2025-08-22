# Shellcraft
# A QoL tool to obfuscate shellcode.
# In the future will be able to chain encoding/encryption/compression methods.
# ~ @0xLegacyy (Jordan Jay)
import argparse
import zlib
import argparse
import base64
import logging
import os
import pyfiglet

from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler

from binascii import hexlify
from itertools import cycle
from os import urandom
from os.path import isfile
from string import hexdigits

from Crypto.Cipher import AES, ARC4, ChaCha20, Salsa20
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


theme = Theme({
    "success" : "spring_green3",
    "info" : "cornflower_blue",
    "error" : "red",
    "exception" : "red",
})
console = Console(theme=theme, color_system="auto")

DEBUG = False

log_path = "logs"
debug_path = "logs/debug_logs.log"
session_path = "logs/session_logs.log"
if not os.path.exists(log_path):
    os.mkdir(log_path)

if not os.path.exists(debug_path):
    with open(debug_path, 'w'): pass

if not os.path.exists(session_path):
    with open(session_path, 'w'): pass

logging.basicConfig(
    level="DEBUG",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True),
        logging.FileHandler(debug_path, mode='a', encoding="utf-8"),
        logging.FileHandler(session_path, mode='w', encoding="utf-8"),
    ],
)

logger = logging.getLogger("rich")


# global vars
OUTPUT_FORMATS = [
    "c",
    "csharp",
    "nim",
    "go",
    "py",
    "ps1",
    "vba",
    "vbscript",
    "raw",
    "rust"
]


CIPHERS = [
    "aes_128",
    "aes_ecb",
    "aes_cbc",
    "chacha20",
    "rc4",
    "salsa20",
    "xor",
    "xor_complex"
]

ENCODING = [
    "alpha32",
    "ascii85",
    "base64",
    "words256"
]

COMPRESSION = [
    "lznt",
    "rle",
]

VERSION = "v1.6"

def show_banner():
    banner = pyfiglet.figlet_format("Shellcrypt", font="slant", justify="left")
    console.print(f"[bold yellow]{banner}{VERSION}\n[/bold yellow]")
    console.print("By:\t\t@0xLegacyy (Jordan Jay)", style="green4")
    console.print("Modified By:\t@Lavender-exe", style="medium_purple1")
    console.print("")


class Log(object):
    """ Handles all styled terminal output. """
    def __init__(self):
        super(Log, self).__init__()
        return

    def logSuccess(msg: str):
        """ Logs msg to the terminal with a green [+] appended.
            Used to show task success.
        :param msg: User-specified message to be output
        :return:
        """
        return logger.debug(f"[+] {msg}")
        # return console.print(f"[+] {msg}", style="success")

    def logInfo(msg: str):
        """ Logs msg to the terminal with a blue [*] appended
            Used to show task status / info.
        :param msg: User-specified message to be output
        :return:
        """
        return logger.info(f"[!] {msg}")
        # return console.print(f"[!] {msg}", style="info")

    def logDebug(msg: str):
        """ Logs msg to the terminal with a magenta [debug] appended
            Used to show debug info for nerds.
        :param msg: User-specified message to be output
        :return:
        """
        if DEBUG:
            return logger.debug(msg=f"[+] {msg}")
            # return console.print(f"[*] {msg}", style="yellow3")

    def logError(msg: str):
        """ Logs msg to the terminal with a red [!] appended
            Used to show error messages.
        :param msg: User-specified message to be output
        :return:
        """
        return logger.error(f"[-] {msg}")
        # return console.print(f"[-] {msg}", style="error")

    def log_exception(msg: str):
        """ Logs msg to the terminal with a red [!!] appended
            Used to show error messages.
        :param msg: User-specified message to be output
        :return:
        """
        return logger.exception(f"[!!] {msg}")


class ShellcodeFormatter(object):
    """ Enables for easy output generation in multiple formats. """
    def __init__(self):
        super(ShellcodeFormatter, self).__init__()
        self.__format_handlers = {
            "c":        self.__output_c,
            "csharp":   self.__output_csharp,
            "nim":      self.__output_nim,
            "go":       self.__output_go,
            "py":       self.__output_py,
            "ps1":      self.__output_ps1,
            "vba":      self.__output_vba,
            "vbscript": self.__output_vbscript,
            "raw":      self.__output_raw,
            "rust":     self.__output_rust
        }
        return

    def __generate_array_contents(self, input_bytes:bytearray, string_format:bool=False) -> str:
        """ Takes a byte array, and generates a string in format
            0xaa,0xff,0xab(up to 15),
            0x4f...
        :param input_bytes: bytearray
        :param string_format: Whether to print in the \xff format or 0xff
        :return: string containing formatted array contents
        """
        # TODO: Rework this to support more languages than just those that use the 0x format
        output = ""
        if not string_format:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n\t"
                output += f"0x{input_bytes[i]:0>2x},"
            output += f"0x{input_bytes[-1]:0>2x}"
            return output[1:] # (strip first \n)
        else:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n"
                output += f"\\x{input_bytes[i]:0>2x}"
            output += f"\\x{input_bytes[-1]:0>2x}"
            return output[1:] # (strip first \n)

    def __output_c(self, arrays:dict) -> str:
        """ Private method to output in C format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in c format, similar
                        to msfvenom's csharp format.
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"unsigned char {array_name}[{len(arrays[array_name])}] = {{\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n};\n\n"

        return output

    def __output_rust(self, arrays:dict) -> str:
        """ Private method to output in Rust format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in rust format, similar
                        to msfvenom's rust format.
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"let {array_name}: [u8; {len(arrays[array_name])}] = [\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n];\n\n"

        return output

    def __output_csharp(self, arrays:dict) -> str:
        """ Private method to output in C# format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in C# format
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"byte[] {array_name} = new byte[{len(arrays[array_name])}] {{\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n};\n\n"

        return output

    def __output_nim(self, arrays:dict) -> str:
        """ Private method to output in nim format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in nim format
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"var {array_name}: array[{len(arrays[array_name])}, byte] = [\n"
            output += "\tbyte " + self.__generate_array_contents(arrays[array_name])[1:]
            output += "\n]\n\n"
        return output

    def __output_go(self, arrays:dict) -> str:
        """ Private method to output in golang format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in golang format
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"{array_name} := []byte{{\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n};\n\n"
        return output

    def __output_py(self, arrays:dict) -> str:
        """ Private method to output in python format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in python format
        """
        # Note: Technically not best to use the triple quotes here but consistency ig
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"{array_name} = b\"\"\""
            output += self.__generate_array_contents(arrays[array_name], string_format=True)
            output += "\"\"\"\n\n"
        return output

    def __output_ps1(self, arrays:dict) -> str:
        """ Private method to output in powershell format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in powershell format
        """
        # Note: Technically not best to use the triple quotes here but consistency ig
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"[Byte[]] ${array_name} = "
            output += self.__generate_array_contents(arrays[array_name])[1:]
            output += "\n\n"
        return output

    def __output_vba(self, arrays:dict) -> str:
        """ Private method to output in visual basic application format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in visual basic application format
        """
        # Generate arrays
        output = str()
        # VBA has a maximum line length of 1023 characters, so have to work around that
        for array_name in arrays:
            # Array name
            output += f"{array_name} = Array("
            line_length = len(output)
            # Array contents
            array_size = len(arrays[array_name])
            for i, x in enumerate(arrays[array_name]):
                if i == array_size - 1:
                    break
                # If within 5 bytes, we have enough to write "222,_", which is enough for any value.
                if line_length + 5 > 1022:
                    output += "_\n"
                    line_length = 0
                output += f"{x},"
                line_length += len(f"{x},")
            # Array end
            if line_length + 4 > 1023:
                output += "_\n"
            output += f"{x})\n\n"
        return output

    def __output_vbscript(self, arrays:dict) -> str:
        """ Private method to output in vbscript format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in vbscript format
        """
        # does not have short line lengths
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"{array_name}="
            output += "".join([f"Chr({str(c)})&" for c in arrays[array_name]])[:-1]
            output += "\n\n"
        return output

    def __output_raw(self, arrays:dict) -> str:
        """ Private method to output shellcode in raw format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in raw format
        """
        # Grab shellcode
        return arrays["sh3llc0d3"]

    def generate(self, output_format:str, arrays:dict) -> str:
        """ Generates output given the current class configuration
        :param output_format: Output format to generate e.g. "c" or "csharp"
        :param shellcode: dictionary containing {"arrayname":array_bytes} pairs
        :return output: string containing formatted shellcode + key(s)
        """
        # Pass execution to the respective handler and return
        return self.__format_handlers[output_format](arrays)


class Encrypt:
    """ Consolidates encryption into a single class. """
    def __init__(self):
        super(Encrypt, self).__init__()
        self.__encryption_handlers = {
            "xor":         self.__xor,
            "xor_complex": self.__xor_complex,
            "aes_128":     self.__aes_128,
            "aes_ecb":     self.__aes_ecb,
            "aes_cbc":     self.__aes_cbc,
            "rc4":         self.__rc4,
            "chacha20":    self.__chacha20,
            "salsa20":     self.__salsa20
        }
        return

    def __random_key(self) -> int:
        LCG_A = 1664525  # Multiplier
        LCG_C = 1013904223  # Increment
        LCG_M = 2**32  # Modulus (2^32)

        self.seed = (LCG_A * self.seed + LCG_C) % LCG_M
        return self.seed & 0xFF

    def encrypt(self, cipher:str, plaintext:bytearray, key:bytearray, nonce:bytearray = None) -> bytearray:
        """ Encrypts plaintext with the user-specified cipher.
            This has been written this way to support chaining of
            multiple encryption methods in the future.
        :param cipher: cipher to use, e.g. 'xor'/'aes'
        :param plaintext: bytearray containing our plaintext
        :param key: bytearray containing our encryption key
        :param nonce: bytearray containing nonce for aes etc.
                      if none will be generated on the fly
        :return ciphertext: bytearray containing encrypted plaintext
        """
        # If nonce not specified, generate one, otherwise use the specified one.
        self.nonce = urandom(16) if nonce is None else nonce
        self.key = key
        # cipher is already validated (check argument validation section).
        return self.__encryption_handlers[cipher](plaintext)

    def __xor(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with a repeating XOR key.
        :param plaintext: bytearray containing our plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        return bytearray(a ^ b for (a, b) in zip(plaintext, cycle(self.key)))

    def __xor_complex(self, plaintext: bytearray) -> bytearray:
        """
        XOR Encrypts/Decrypts given shellcode using a Linear Congruential Generator (LCG)
        """
        encrypted_shellcode = bytearray()
        for byte in plaintext:
            random_key = self.__random_key()
            encrypted_shellcode.append(byte ^ random_key)

        return encrypted_shellcode

    def __aes_128(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with AES-128 in CBC mode.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        aes_cipher = AES.new(self.key, AES.MODE_CBC, self.nonce)
        plaintext = pad(plaintext, 16)
        return bytearray(aes_cipher.encrypt(plaintext))

    def __rc4(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via RC4.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        rc4_cipher = ARC4.new(self.key)
        return rc4_cipher.encrypt(plaintext)

    def __chacha20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via ChaCha20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        chacha20_cipher = ChaCha20.new(key=self.key)
        return chacha20_cipher.encrypt(plaintext)

    def __salsa20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via Salsa20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        salsa20_cipher = Salsa20.new(key=key)
        return salsa20_cipher.encrypt(plaintext)

    def __aes_ecb(self, plaintext:bytearray) -> bytearray:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)
        return cipher.encrypt(padded_shellcode)

    def __aes_cbc(self, plaintext:bytearray) -> bytearray:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)

        encrypted_shellcode = cipher.encrypt(padded_shellcode)
        return bytearray(iv) + bytearray(encrypted_shellcode)


class Compress:
    def __init__(self):
        super(Compress, self).__init__()
        self.__compression_handlers = {
            "lznt": self.__lznt_compress,
            "rle":  self.__rle_compress
        }
        self.__decompression_handlers = {
            "lznt": self.__lznt_decompress,
            "rle":  self.__rle_decompress
        }
        return

    def compress(self, compression: str, data: bytearray) -> bytearray:
        return self.__compression_handlers[compression](data)

    def decompress(self, decompression: str, data: bytearray) -> bytearray:
        return self.__decompression_handlers[decompression](data)

    def __lznt_compress(self, data: bytearray) -> bytearray:
        return bytearray(zlib.compress(data))

    def __lznt_decompress(self, data: bytearray) -> bytearray:
        return bytearray(zlib.decompress(data))

    def __rle_compress(self, data: bytearray) -> bytearray:
        compressed = bytearray()
        count = 1
        for index in range(1, len(data)):
            if data[index] == data[index - 1]:
                count += 1
            else:
                compressed.append(data[index-1])
                compressed.append(count)
                count = 1

        compressed.append(data[index-1])
        compressed.append(count)
        return compressed

    def __rle_decompress(self, data: bytearray) -> bytearray:
        decompressed = bytearray()
        index = 0
        while index < len(data):
            byte = data[index]
            count = data[index + 1]
            decompressed.extend([byte] * count)
            index += 2
        return decompressed


class Encode:
    def __init__(self):
        super(Encode, self).__init__()
        self.__encoding_handlers = {
            "base64": self.__base64_encode,
            "ascii85": self.__ascii85_encode,
            "alpha32": self.__alpha32_encode,
            "words256": self.__words256_encode
        }
        self.__decoding_handlers = {
            "base64": self.__base64_decode,
            "ascii85": self.__ascii85_decode,
            "alpha32": self.__alpha32_decode,
            "words256": self.__words256_decode
        }
        return

    def encode(self, encoding: str, data: bytearray) -> bytearray:
        return self.__encoding_handlers[encoding](data)

    def decode(self, decoding: str, data: bytearray) -> bytearray:
        return self.__decoding_handlers[decoding](data)

    def __base64_encode(self, data: bytearray) -> bytearray:
        encoded = base64.b64encode(data)
        return bytearray(encoded)

    def __base64_decode(self, data: bytearray) -> bytearray:
        decoded = base64.b64decode(data)
        return bytearray(decoded)

    def __ascii85_encode(self, data: bytearray) -> bytearray:
        encoded = base64.a85encode(data)
        return bytearray(encoded)

    def __ascii85_decode(self, data: bytearray) -> bytearray:
        decoded = base64.a85decode(data)
        return bytearray(decoded)

    def __alpha32_encode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        encoded = bytearray()
        for byte in data:
            encoded.extend(alphabet[byte % len(alphabet)].encode())
        return encoded

    def __alpha32_decode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        decoded = bytearray()
        for char in data:
            decoded.append(alphabet.index(chr(char)))
        return decoded

    def __words256_encode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        encoded = bytearray()
        for byte in data:
            encoded.extend(words[byte % len(words)].encode() + b" ")
        return encoded

    def __words256_decode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        decoded = bytearray()
        word = b""
        for byte in data:
            word += bytes([byte])
            if word.endswith(b" "):  # Word boundary (space)
                decoded.append(words.index(word.decode().strip()))
                word = b""
        return decoded


def parse_args():
    # Parse arguments
    # TODO: Add --preserve-null flag for XOR. (Don't XOR null bytes.)
    # TODO: Add length param for random key, currently locked at 16 bytes.
    # TODO: Maybe add decryption routines?

    argparser = argparse.ArgumentParser(prog="shellcrypt")
    argparser.add_argument("-i", "--input", help="Path to file to be encrypted.")
    argparser.add_argument("-e", "--encrypt", default="xor", help="Encryption method to use, default 'xor'.")
    argparser.add_argument("-d", "--encode", default=None, help="Encoding method to use, default.")
    argparser.add_argument("-c", "--compress", default=None, help="Compression method to use.")
    argparser.add_argument("-k", "--key", help="Encryption key in hex format, default (random 16 bytes).")
    argparser.add_argument("-n", "--nonce", help="Encryption nonce in hex format, default (random 16 bytes).")
    argparser.add_argument("-f", "--format", help="Output format, specify --formats for a list of formats.")
    argparser.add_argument("--formats", action="store_true", help="Show a list of valid formats")
    argparser.add_argument("--ciphers", action="store_true", help="Show a list of valid ciphers")
    argparser.add_argument("--encoders", action="store_true", help="Show a list of valid encoders")
    argparser.add_argument("--compressors", action="store_true", help="Show a list of valid compressors")
    argparser.add_argument("-o", "--output", help="Path to output file")
    argparser.add_argument("-v", "--version", action="store_true", help="Shows the version and exits")

    return argparser.parse_args()

def main():
    # Completely unnecessary stuff (unless you're cool)
    show_banner()
    args = parse_args()

    # --------- Info-only arguments ---------
    # If formats specified
    if args.formats:
        print("The following formats are available:")
        for i in OUTPUT_FORMATS:
            print(f" - {i}")
        exit()

    # If ciphers specified
    if args.ciphers:
        print("The following ciphers are available:")
        for i in CIPHERS:
            print(f" - {i}")
        exit()

    # If encoding specified
    if args.encoders:
        print("The following encoders are available:")
        for i in ENCODING:
            print(f" - {i}")
        exit()

    # If compression specified
    if args.compressors:
        print("The following compressors are available:")
        for i in COMPRESSION:
            print(f" - {i}")
        exit()

    # If version specified
    if args.version:
        print(VERSION)
        exit()

    # --------- Argument Validation ---------
    Log.logDebug(msg="Validating arguments")

    # Check input file is specified
    if args.input is None:
        Log.logError("Must specify an input file e.g. -i shellcode.bin (specify --help for more info)")
        exit()

    # Check input file exists
    if not isfile(args.input):
        Log.logError(f"Input file '{args.input}' does not exist.")
        exit()

    # TODO: check we can read the file.

    Log.logSuccess(f"Input file: '{args.input}'")

    # Check format is specified
    if args.format not in OUTPUT_FORMATS:
        Log.logError("Invalid format specified, please specify a valid format e.g. -f c (--formats gives a list of valid formats) ")
        exit()

    Log.logSuccess(f"Output format: {args.format}")

    # Check encrypt is specified
    if args.encrypt not in CIPHERS:
        Log.logError("Invalid cipher specified, please specify a valid cipher e.g. -e xor (--ciphers gives a list of valid ciphers) ")
        exit()

    if args.encode:
        if args.encode not in ENCODING:
            Log.logError("Invalid encoder specified, please specify a valid encoder e.g. -d ascii85 (--encoders gives a list of valid encoders) ")
            exit()

    if args.compress:
        if args.compress not in COMPRESSION:
            Log.logError("Invalid compression specified, please specify a valid compression e.g. -c lznt (--compressors gives a list of valid compressors) ")
            exit()

    Log.logSuccess(f"Output Encoding: {args.encode}")
    Log.logSuccess(f"Output Encryption: {args.encrypt}")
    Log.logSuccess(f"Output Compression: {args.compress}")

    # Check if key is specified.
    # if so => validate and store in key
    # else => generate and store in key
    if args.key is None:
        key = urandom(32) # Changed from 8 to 16 to make AES support easier :)
    else:
        if len(args.key) < 2 or len(args.key) % 2 == 1:
            Log.logError("Key must be valid byte(s) in hex format (e.g. 4141).")
            exit()
        if args.encrypt == "aes" and len(args.key) != 32:
            Log.logError("AES-128 key must be exactly 16 bytes long.")
            exit()
        for i in args.key:
            if i not in hexdigits:
                Log.logError("Key must be valid byte(s) in hex format (e.g. 4141).")
                exit()

        key = bytearray.fromhex(args.key)

    Log.logSuccess(f"Using key: {hexlify(key).decode()}")

    # TODO: somehow join the above and this as it's a lot of repeated code,
    #       maybe some kind of method for checking if an input is hex and 16 bytes ?
    # Validate the user's nonce if one is specified, else generate one
    if args.nonce is None:
        nonce = urandom(16)
    else:
        if len(args.nonce) != 32:
            Log.logError("Nonce must be exactly 16 bytes long")
            exit()
        for i in args.nonce:
            if i not in hexdigits:
                Log.logError("Nonce must be 16 valid bytes in hex format (e.g. 7468697369736d616c6963696f757321)")
                exit()

        nonce = bytearray.fromhex(args.nonce)

    # Only show nonce if it's used, could be confusing to the user otherwise
    # TODO: probably change this in the future to if args.encrypt in requires_nonce => show
    if args.encrypt == "aes":
        Log.logSuccess(f"Using nonce: {hexlify(nonce).decode()}")

    Log.logDebug("Arguments validated")

    # --------- Read Input File ---------
    input_bytes = None

    with open(args.input, "rb") as input_handle:
        input_bytes = input_handle.read()

    # --------- Input File Encryption ---------
    #Log.logInfo(f"Encrypting {len(input_bytes)} bytes") (came up with a better idea, keeping for future reminder)
    if args.encode: Log.logDebug("Encoding input file")
    if args.encrypt: Log.logDebug("Encrypting input file")
    if args.compress: Log.logDebug("Compressing input file")

    #input_bytes  = bytearray(a ^ b for (a, b) in zip(input_bytes, cycle(key)))
    cryptor = Encrypt()
    compressor = Compress()
    encoder = Encode()

    input_bytes = encoder.encode(args.encode, input_bytes)
    encrypted_bytes = cryptor.encrypt(args.encrypt, input_bytes, key, nonce)
    compressed_bytes = compressor.compress(args.compress, encrypted_bytes)

    Log.logSuccess(f"Successfully encrypted input file ({len(compressed_bytes)} bytes)\n")

    # --------- Output Generation ---------
    # Define array names + content to be formatted
    arrays = {
        "key":key
    }

    # If aes in use, add nonce to the arrays
    if args.encrypt == "aes_128" or args.encrypt == "aes_ecb" or args.encrypt == "aes_cbc":
        arrays["nonce"] = nonce

    # Removed from the initialization line(s) for arrays for nicer output ordering.
    arrays["sh3llc0d3"] = compressed_bytes

    # Generate formatted output.
    shellcode_formatter = ShellcodeFormatter()
    output = shellcode_formatter.generate(args.format, arrays)

    # --------- Output ---------
    # If no output file specified.
    if args.output is None:
        # We want to decode if it's a bytearray. (for raw mode)
        console.print(output.decode("latin1") if isinstance(output, bytearray) else output)
        exit()

    # If output file specified.
    Log.logDebug(f"output var type: {type(output)}")

    write_mode = ("wb" if isinstance(output, bytearray)
                  else "w") # We want wb if it's a bytearray. (for raw mode)
    Log.logDebug(f"write_mode = \"{write_mode}\"")
    with open(args.output, write_mode) as file_handle:
        file_handle.write(output)

    Log.logSuccess(f"Output written to '{args.output}'")


if __name__ == "__main__":
    # --------- Initialisation ---------
    # Debug mode toggle (logging)
    main()