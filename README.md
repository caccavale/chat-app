# chat-server

___This might require Python 3.7 or newer.___

This was a test in building a "secure" chat app using only networking and crypto primitives.  All networking is done over UDP sockets and all crypto is from `cryptography.hazmat`.  It shouldn't be used, but was a learning exercise in designing and implementing a "secure" protocol from near scratch.  There are still `TODO`s sprinkled around and I'm sure that it has some vulnerabilites.

### Installation:
I recommend using a virtual environment, though it is not necessary.
```
python3 -m virtualenv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

### Getting started:
While sourcing your virtual environment:

To seed user and server RSA keys, use `python3 ChatServer.py -n`.  This creates four users: `[Alice, Bob, Charlie, Eve]` whose passwords are the same as their usernames.  This will overwrite existing keys and will break currently running clients and servers.

To start the server, use `python3 ChatServer.py -sp <port>` and it will be hosted at `127.0.0.1:<port>`.

To start a client, use `python3 ChatClient.py -u Bob -p Bob -sip 127.0.0.1 -sp 5000`  Where `-u` is the username, `-p` is the password, `-sip` is the server ip, `-sp` is the server port.

Once connection has been established, a client may use the commands `list` and `send`.  `list` will get a list of online users from the server while `send <user> <message>` will send `<message>` to the online `<user>`.

### Security summary:

Once a clients has been started, it will complete two challenges for the server.  The first is a proof of work which for completing it will receive some encrypted credentials.  After decrypting these credentials it will complete a second challenge which verifies it has decrypted them with a key derived from their password.  This acts as authenticity.

```
c -> s: {I would like a challenge}S_pub
s <- c: [c1]S where c1 = n1||d||timestamp
c -> s: {username||[c1]S||X}S_pub where the first d bytes of sha256(n1||X) are 0's
c <- s: [C_pub||{C_pri}K||[c2]S]S where c2 = n2||timestamp
c computes K = HKDF(password), uses K to decrypt C_pri
c -> s: {username||[c1]S||[c1]C}
c <- s: [manifest]S
```

Client to client communication is done via typical RSA-AES-GCM:
```
a -> b: username||[{message}(Key, IV)||{Key, IV}B_pub]A
```

### Technical overview:

All networking is done over UDP sockets which have been abstracted over twice.

The first abstraction is in `protocols/internet` which emulates IP packets and connections with packet level integrity.

The second abstraction is in `protocols/transport` which emulates TCP packets and connections with fragmentation, ordering, and multiplexing.

By `protocols/applications` arbitrarily lengthed data can be reliably sent to any number of sockets.  _A couple race conditions exist, but only allow DOS type vulnerabilities._

### Additional packages:

I use `cryptography` for its crypto primitives and `construct` for symmetric data packing/unpacking (its a more featured `struct` library).

### Known bugs:
If you send a message to someone who is offline, you will be unable to send them any messages until you restart your client.
