# FortiGate rootfs decryption tool (by optistream.io)

On recent FortiGate firmwares versions, `rootfs.gz` is checked against a signature then decrypted using ChaCha20.  
This is implemented inside the kernel (`flatkc`) within function `fgt_verify_decrypt`.

- `getrootfskey.py`: retrieve encryption key from kernel
- `decrypt_rootfs`/`encrypt_rootfs`: decrypt/encrypt `rootfs.gz` using previously retrieved encryption key
- `decrypt_rsapubkey`: auxiliary tool for decrypting RSA public key embedded in kernel for rootfs signature check (`fgt_verifier_pub_key`)

Tested on: FortiOS 7.4.2, 7.4.3 (x64 & aarch64)

## 0. Build

```bash
$ sudo apt install libssl-dev
$ make
```

## 1. Get rootfs encryption key from kernel

This script actually analyzes `fgt_verifier_pub_key` function to retrieve encryption seed (using `miasm==0.1.5`):

```bash
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install miasm
$ python getrootfskey.py flatkc.elf.x64.v7.4.3
Architecture: x86_64
Seed address: 0xffffffff817932e0
Extracted seed: b'4CF7A950B99CF29B0343E7BA6C609E49D9766F16C6D2F075F72AD400542F0765'
```

## 2. Decrypt/encrypt `rootfs`

```bash
$ ./decrypt_rootfs rootfs.gz.x64.v7.4.3 rootfs.gz.x64.v7.4.3.decrypted 4CF7A950B99CF29B0343E7BA6C609E49D9766F16C6D2F075F72AD400542F0765
833E9BAFBF0C2F581E9A949B13C4352B9D52C72A27B925EA3B46F8236BFF58F1
8C575F183A1AD583BDDD9A822A8A5D4E312452509E322FA46283A9EAF7E30BF6
rootfs size: 71395069
Decrypting rootfs...
Writing to rootfs.gz.x64.v7.4.3.decrypted...
```

# Links

[https://github.com/Ginurx/chacha20-c](https://github.com/Ginurx/chacha20-c)

[https://github.com/cea-sec/miasm](https://github.com/cea-sec/miasm)

# Author

[https://optistream.io](https://optistream.io)
