import argparse
from protocols.applications import Client

parser = argparse.ArgumentParser()
parser.add_argument('-u', dest='user', type=str)
parser.add_argument('-p', dest='password', type=str)
parser.add_argument('-sip', dest='ip', type=str)
parser.add_argument('-sp', dest='port', type=int)
args = parser.parse_args()

connection = Client(args.ip, args.port, args.user, args.password)
