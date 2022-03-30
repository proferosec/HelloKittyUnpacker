# HelloKittyUnpacker
A tool to assist in analysis of packed HelloKitty ransomware binaries

# Compiling

To compile the tool, execute the following:

```bash
gcc DecryptData.c aes.c -o unpacker.exe
```

# Usage

```
Usage : ./main <input_file> <key> <output_file>
```
