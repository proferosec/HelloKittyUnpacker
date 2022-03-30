# HelloKittyUnpacker
A tool to assist in analysis of packed HelloKitty ransomware binaries

# Compiling

To compile the tool, execute the following:

```bash
gcc DecryptData.c aes.c -o HelloKittyUnpacker.exe
```

# Usage

```
Usage : ./HelloKittyUnpacker.exe <input_file> <key> <output_file>
```

The tool will then print information about the packed file including the sections found in the packed file, the IV used for decryption, the C2 address and the RSA key.
