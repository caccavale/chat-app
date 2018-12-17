"""
This is the application layer implementation of the chat server.  At this point,
packets are abstracted over and arbitrarily sized data can be sent over an arbitrary
number of connections.
"""
from enum import IntEnum

from typing import Union
from protocols.transport import Multiplexer
from common.crypto import Notary
from common import loadb, dumpb
from cryptography.exceptions import InvalidTag

class MessageType(IntEnum):
    CHALLENGE_REQUEST = 1
    CHALLENGE_ISSUED = 2
    CHALLENGE_RESPONSE = 3
    CREDENTIALS_ISSUED = 4
    LOGIN_REQUEST = 5
    LOGIN_RESPONSE = 6
    LIST_REQUEST = 7
    LIST_RESPONSE = 8

CONFIG = {
    'server_public_key': 'server.pub',
    'server_private_key': 'server',

    'manifest': 'manifest',

    'server_address': '127.0.0.1'
}


def setup_locals():
    notary = Notary()

    with open(CONFIG['server_private_key'], 'wb') as private, \
            open(CONFIG['server_public_key'], 'wb') as public:
        private_key, public_key = Notary.keygen()
        private.write(private_key)
        public.write(public_key)

    manifest = {}
    for user in ['Alice', 'Bob', 'Charlie', 'Eve']:
        private_key, public_key = notary.keygen()
        user_info = {
            'password': user.encode(),
            'public_key': public_key
        }
        user_info.update(notary.hide_key(private_key, notary.derive_key(user.encode())))

        manifest[user] = user_info

    with open(CONFIG['manifest'], 'wb') as f:
        f.write(dumpb(manifest))


class Server:
    def __init__(self, port):
        self.users = {}

        self.handlers = {
            MessageType.CHALLENGE_REQUEST: self.handle_challenge_request,
            MessageType.CHALLENGE_RESPONSE: self.handle_challenge_response,
            MessageType.LOGIN_REQUEST: self.handle_login_request,
            MessageType.LIST_REQUEST: self.handle_list_request,
            None: self.error,
        }

        self.notary = Notary()
        with open(CONFIG['server_public_key'], 'rb') as f:
            self.notary.raw_public_key = f.read()
        with open(CONFIG['server_private_key'], 'rb') as f:
            self.notary.raw_private_key = f.read()
        self.notary.load_keys()
        print('Keys obtained...')

        with open(CONFIG['manifest'], 'rb') as f:
            self.manifest = loadb(f.read())
        print('Manifest collected...')

        self.connection = Multiplexer(
            (CONFIG['server_address'], port),
            self.handle_messages)
        print('Server Initialized...')

    def handle_messages(self, message: Union[str, bytes], source):
        message = loadb(self.notary.decrypt(loadb(message)))
        message['source'] = source
        self.handlers[message.get('type')](message)

    def send(self, j, destination):
        message = {
            'contents': j,
            'signature': self.notary.sign(dumpb(j)),
        }
        self.connection.send(dumpb(message), destination)

    def handle_challenge_request(self, message):
        print('handling challenge request')
        challenge = self.notary.issue_challenge()
        challenge['type'] = MessageType.CHALLENGE_ISSUED
        self.send(challenge, message['source'])

    def handle_challenge_response(self, message):
        print('handling challenge response for %s' % message.get('username').decode())
        if not self.notary.verify_challenge(message):
            print("Invalid challenge")
            return

        username = message.get('username')
        if username is None:
            print('No user specified')
            return

        user_info = self.manifest.get(username.decode())
        if user_info is None:
            print('No user exists: %s' % username)
            return

        user_info['type'] = MessageType.CREDENTIALS_ISSUED
        user_info.update(self.notary.issue_proof())

        self.send(user_info, message['source'])

    def handle_login_request(self, message):
        print('handling login request for %s' % message.get('username').decode())
        username = message.get('username')
        if username is None:
            print('No user specified')
            return

        user_info = self.manifest.get(username.decode())
        if user_info is None:
            print('No user exists: %s' % username)
            return

        public_key = user_info.get('public_key')
        if public_key is None:
            print('User info is corrupted')
            return

        if not self.notary.verify_proof(message, public_key):
            print('Invalid proof')
            return False

        self.users[username.decode()] = message['source']

        response = {
            'type': MessageType.LOGIN_RESPONSE,
            'manifest': self.manifest,
        }
        self.send(response, message['source'])

    def handle_list_request(self, message):
        print('handling list request')
        response = {
            'type': MessageType.LIST_RESPONSE,
            'users': self.users,
        }
        self.send(response, message['source'])

    def error(self, message):
        print("Couldn't handle: %s" % str(message))


class Client:
    def __init__(self, server_ip, server_port, username, password):
        self.handlers = {
            MessageType.CHALLENGE_ISSUED: self.handle_challenge,
            MessageType.CREDENTIALS_ISSUED: self.handle_credentials,
            MessageType.LOGIN_RESPONSE: self.handle_login,
            MessageType.LIST_RESPONSE: self.handle_list,
            None: self.error,
        }

        if server_ip is 'localhost':
            server_ip = '127.0.0.1'
        self.server = (server_ip, server_port)
        self.username = username.encode()

        with open(CONFIG['server_public_key'], 'rb') as f:
            self.raw_server_public_key = f.read()

        self.connection = Multiplexer(None, self.receive_message)
        self.notary = Notary()
        self.key = self.notary.derive_key(password.encode())
        self.manifest = {}

        self.users = {}
        try:
            self.send_to_server({'type': MessageType.CHALLENGE_REQUEST})

            while True:
                self.handle_message(input('+> '))
        except KeyboardInterrupt:
            exit(0)

    def send_to_server(self, j):
        #print(dumpb(j))
        #print(dumpb(self.notary.encrypt(dumpb(j),self.raw_server_public_key)))
        self.connection.send(
            dumpb(
                self.notary.encrypt(
                    dumpb(j),
                    self.raw_server_public_key)),
            self.server)

    def receive_message(self, message: Union[str, bytes], source):
        message = loadb(message)
        message['source'] = source

        if message['source'] == self.server:
            #print('Server message')
            if not self.notary.verify(dumpb(message['contents']),
                                      message['signature'],
                                      self.raw_server_public_key):
                #print('Invalid message from server')
                return

            message = message['contents']
            self.handlers[message['type']](message)

        else:
            sender = message['username'].decode()
            if sender not in self.users:
                self.users[message['username'].decode()] = tuple(message['source'])

            if not self.notary.verify(dumpb(message['bundle']),
                                      message['signature'],
                                      self.manifest[sender]['public_key']):
                print('Unauthentic message sent from %s as user %s' %
                      (str(message['source']), sender))
                return

            plaintext = self.notary.decrypt(message['bundle'])
            print('%s > %s' % (sender, plaintext.decode()))

    def handle_challenge(self, message):
        #print(message)
        message = self.notary.solve_challenge(message)
        message['type'] = MessageType.CHALLENGE_RESPONSE
        message['username'] = self.username
        self.send_to_server(message)

    def handle_credentials(self, message):
        self.notary.raw_public_key = message['public_key']
        try:
            self.notary.raw_private_key = self.notary.recover_key(message, self.key)
        except InvalidTag:
            print('Invalid password.')

        self.notary.load_keys()

        message = self.notary.solve_proof(message)
        message['type'] = MessageType.LOGIN_REQUEST
        message['username'] = self.username
        self.send_to_server(message)

    def handle_login(self, message):
        self.manifest = message['manifest']

    def handle_list(self, message):
        self.users = {}
        print(message['users'])

        for user, address in message['users'].items():
            self.users[user] = tuple(address)

    def error(self, message):
        print("Couldn't handle: %s" % str(message))

    def handle_message(self, text):
        tokens = text.split(' ')
        if tokens[0] == 'list':
            self.send_to_server({'type': MessageType.LIST_REQUEST})
        elif tokens[0] == 'send':
            if tokens[1] in self.users:
                self.send_to_user(tokens[1], ' '.join(tokens[2:]))
            else:
                print('User is not online, try using `list` to update online users')
        else:
            print('Not a valid command.')

    def send_to_user(self, username, message_text):
        public_key = self.manifest[username]['public_key']
        #print(public_key)
        bundle = self.notary.encrypt(message_text, public_key)
        signature = self.notary.sign(dumpb(bundle))
        message = {
            'username': self.username,
            'bundle': bundle,
            'signature': signature
        }
        self.connection.send(dumpb(message), self.users[username])
