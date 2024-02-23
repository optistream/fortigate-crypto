CC=gcc
DEPS=chacha20.c chacha20.h
LDFLAGS=-lssl -lcrypto
all: decrypt_rootfs encrypt_rootfs decrypt_rsapubkey

decrypt_rootfs: decrypt_rootfs.c $(DEPS)
	$(CC) $^ -o $@ $(LDFLAGS)
encrypt_rootfs: encrypt_rootfs.c $(DEPS)
	$(CC) $^ -o $@ $(LDFLAGS)
decrypt_rsapubkey: decrypt_rsapubkey.c $(DEPS)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f decrypt_rootfs encrypt_rootfs decrypt_rsapubkey
	