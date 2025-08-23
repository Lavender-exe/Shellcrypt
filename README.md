# Shellcrypt

A single-file cross-platform quality of life tool to obfuscate a given shellcode file and output in a useful format for pasting directly into your source code.

![Screenshot of Shellcrypt encrypting shellcode](https://i.imgur.com/DavG7ad.png)

## Contributors

These are going here because they deserve it
- An00bRektn [github](https://github.com/An00bRektn) [twitter](https://twitter.com/An00bRektn) ♥
- 0xtejas [github](https://github.com/0xtejas)
- Lavender-exe [github](https://github.com/Lavender-exe)

## Encryption Methods

Shellcrypt currently supports the following encryption methods (more to come in the future!)

- AES CBC - 128
- AES CBC - 256
- AES ECB - 256
- ChaCha20
- RC4
- Salsa20
- XOR
- XOR with Linear Congruential Generator (LCG)

## Supported Formats

Shellcrypt currently supports the following output formats (more to come in the future!)

- C
- C#
- Nim
- Golang
- Python
- Powershell
- Visual Basic for Applications (VBA)
- Visual Basic Script (VBS)
- Rust
- Raw

## Usage 
**Encrypt shellcode with a random key**
```bash
python ./shellcrypt.py -i ./shellcode.bin -f c
```
**Encrypt shellcode with 128-bit AES CBC**
```bash
python ./shellcrypt.py -i ./shellcode.bin -e aes -f c
```
**Encrypt shellcode with a user-specified key**
```bash
python ./shellcrypt.py -i ./shellcode.bin -f c -k 6d616c77617265
```
**Output in nim format**
```bash
python ./shellcrypt.py -i ./shellcode.bin -f nim
```
**Output to file**
```bash
python ./shellcrypt.py -i ./shellcode.bin -f nim -o ./shellcode_out.nim
```
**Get a list of compression methods**
```bash
python ./shellcrypt.py --compressors
```
**Get a list of encoding methods**
```bash
python ./shellcrypt.py --encoders
```
**Get a list of encryption methods**
```bash
python ./shellcrypt.py --ciphers
```
**Get a list of output formats**
```bash
python ./shellcrypt.py --formats
```

**Help**
```plaintext
   _____ __         ____                      __
  / ___// /_  ___  / / /___________  ______  / /_
  \__ \/ __ \/ _ \/ / / ___/ ___/ / / / __ \/ __/
 ___/ / / / /  __/ / / /__/ /  / /_/ / /_/ / /_
/____/_/ /_/\___/_/_/\___/_/   \__, / .___/\__/
                              /____/_/
v2.0 - Release

By: @0xLegacyy (Jordan Jay)

usage: shellcrypt [-h] -i INPUT [-e ENCRYPT] [--decrypt] [-d ENCODE] [-c COMPRESS] [-k KEY] [-n NONCE] [-f FORMAT] [--formats] [--ciphers] [--encoders] [--compressors] [-o OUTPUT] [-v] [--preserve-null]
                  [--key-length KEY_LENGTH]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to file to be encrypted.
  -e ENCRYPT, --encrypt ENCRYPT
                        Encryption method to use, default 'xor'.
  --decrypt             Enable decryption functionality (not yet implemented).
  -d ENCODE, --encode ENCODE
                        Encoding method to use, default None.
  -c COMPRESS, --compress COMPRESS
                        Compression method to use.
  -k KEY, --key KEY     Encryption key in hex format, default (random 16 bytes).
  -n NONCE, --nonce NONCE
                        Encryption nonce in hex format, default (random 16 bytes).
  -f FORMAT, --format FORMAT
                        Output format, specify --formats for a list of formats.
  --formats             Show a list of valid formats
  --ciphers             Show a list of valid ciphers
  --encoders            Show a list of valid encoders
  --compressors         Show a list of valid compressors
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -v, --version         Shows the version and exits
  --preserve-null       Avoid XORing null bytes during XOR encryption.
  --key-length KEY_LENGTH
                        Specify the key length in bytes (default is 16).
```

## Future Development Goals

- [x] More output formats (rust etc.)
- [x] More encryption methods
- [x] Compression methods
- [ ] Create a config system that allows for chaining encryption/encoding/compression methods
- [ ] Flag to add a decrypt method to the generated code
- [ ] [Shikata](https://github.com/EgeBalci/sgn) encoder mayhaps?

_**pssst** this is still heavily in development so if you'd like to contribute, have a go at working on one of the many `TODO`'s in the code :)_
