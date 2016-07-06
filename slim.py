import sys
from argparse import ArgumentParser
from slim.utils import config
from slim.server import Listener


def main():
    parser = ArgumentParser()
    parser.add_argument('-c', '--config', help='config file')

    args = parser.parse_args(sys.argv[1:])
    if args.config:
        config.__setup(args.config)

    l = Listener()
    l.run()


if __name__ == '__main__':
    sys.exit(main())
