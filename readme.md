
```bash
gcc -o main main.c AES.c CRC.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto && ./main
```