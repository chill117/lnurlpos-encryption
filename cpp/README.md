
Compile program:
```bash
g++ -o xor_encrypt \
	./xor_encrypt.cpp \
	./src/*.cpp \
	./src/utility/*.c \
	./src/utility/trezor/*.c
```

Run:
```bash
./xor_encrypt
```

Example output:
```
http://localhost:3000/lnurl?p=AQhnxmlzUf9K7AVCqW-g6FZRpFw46ght
```
Where `p=<PAYLOAD>`
