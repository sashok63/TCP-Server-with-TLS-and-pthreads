# TCP-Server-with-TLS-and-pthreads
* TCP Server with TLS encryption and pthreads

## Building 
```bash
make
```

## Usage
```bash
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem - generate encryption

./server <port> - on Linux to open the server on port

openssl s_client -connect localhost:<port> - connect to server
```

### Server
Ctrl + C -  shutdown server

### Client
!exit - exit from server

Ctrl + C - exit from server
