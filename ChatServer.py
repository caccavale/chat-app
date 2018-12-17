import argparse
from protocols.applications import Server, setup_locals

parser = argparse.ArgumentParser()
parser.add_argument('-sp', dest='port', type=int)
parser.add_argument('-n', dest='new', nargs='?', const=True, type=bool, default=False)
args = parser.parse_args()

if args.new:
    setup_locals()
    exit(0)

server = Server(args.port)