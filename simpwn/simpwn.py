from typing import Any, Callable, Iterator, Protocol, Self, Type, cast
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from functools import wraps


class Config:
    from pathlib import Path

    env: dict[str, str] = {}
    aslr: bool = True
    dbg: str = ''
    script: str = str(Path(__file__).parent.joinpath('init.dbg'))
    opt: list[str] = []
    term: list[str] = ['tmux', 'split', '-h']
    gdb: str = 'gdb'
    rr: str = 'rr'
    sendfmt: str = '{GREEN}{BOLD}<{END}{END} {CYAN}{0:04x}:{END} {1:!b}  {2:!b} | {1:!ul} {2:!ul} | {1:!s}{2:!s}'
    recvfmt: str = '{PURPLE}{BOLD}>{END}{END} {CYAN}{0:04x}:{END} {1:!b}  {2:!b} | {1:!ul} {2:!ul} | {1:!s}{2:!s}'
    peepfmt: str = '{RED}{BOLD}[L{0}]{END}{END} {1} = {2:#018x}'

    @classmethod
    def init(cls):
        from pathlib import Path

        path = [
            '~/.simpwn.json',
            str(Path(__file__).parent.joinpath('simpwn.json'))
        ]

        for i in path:
            try:
                cls.load(i)
            except FileNotFoundError:
                pass

    @classmethod
    def load(cls, path: str):
        from json import load

        with open(path) as fd:
            data = load(fd)

        for (k, v) in data.items():
            try:
                setattr(cls, k, v)
            except AttributeError:
                pass

    @classmethod
    def quiet(cls):
        cls.sendfmt = ''
        cls.recvfmt = ''
        cls.peepfmt = ''


_INT8_MIN: int = -(1 << 7)
_INT16_MIN: int = -(1 << 15)
_INT32_MIN: int = -(1 << 31)
_INT64_MIN: int = -(1 << 63)
_UINT8_MAX: int = (1 << 8)-1
_UINT16_MAX: int = (1 << 16)-1
_UINT32_MAX: int = (1 << 32)-1
_UINT64_MAX: int = (1 << 64)-1
_BYTEORDER: tuple[str, str] = ('little', 'big')


def p8(value: int) -> bytes:
    assert (_INT8_MIN <= value <= _UINT8_MAX)
    return (value & _UINT8_MAX).to_bytes(length=1)


def p16(value: int, be: bool = False) -> bytes:
    assert (_INT16_MIN <= value <= _UINT16_MAX)
    return (value & _UINT16_MAX).to_bytes(length=2, byteorder=_BYTEORDER[be])


def p32(value: int, be: bool = False) -> bytes:
    assert (_INT32_MIN <= value <= _UINT32_MAX)
    return (value & _UINT32_MAX).to_bytes(length=4, byteorder=_BYTEORDER[be])


def p64(value: int, be: bool = False) -> bytes:
    assert (_INT64_MIN <= value <= _UINT64_MAX)
    return (value & _UINT64_MAX).to_bytes(length=8, byteorder=_BYTEORDER[be])


def pf(value: float, be: bool = False) -> bytes:
    from struct import pack
    format = ('<f', '>f')
    return pack(format[be], value)


def pd(value: float, be: bool = False) -> bytes:
    from struct import pack
    format = ('<d', '>d')
    return pack(format[be], value)


def u8(data: bytes, signed: bool = False) -> int:
    assert (len(data) == 1)
    return int.from_bytes(data, signed=signed)


def u16(data: bytes, signed: bool = False, be: bool = False) -> int:
    assert (len(data) == 2)
    return int.from_bytes(data, signed=signed, byteorder=_BYTEORDER[be])


def u32(data: bytes, signed: bool = False, be: bool = False) -> int:
    assert (len(data) == 4)
    return int.from_bytes(data, signed=signed, byteorder=_BYTEORDER[be])


def u64(data: bytes, signed: bool = False, be: bool = False) -> int:
    assert (len(data) == 8)
    return int.from_bytes(data, signed=signed, byteorder=_BYTEORDER[be])


def uf(data: bytes, be: bool = False) -> int:
    from struct import unpack
    assert (len(data) == 4)
    format = ('<f', '>f')
    return unpack(format[be], data)[0]


def ud(data: bytes, be: bool = False) -> int:
    from struct import unpack
    assert (len(data) == 8)
    format = ('<d', '>d')
    return unpack(format[be], data)[0]


def flat(*args: bytes) -> bytes:
    return b''.join(args)


def block(size: int, *pair: tuple[int, bytes]) -> bytes:
    dst = bytearray(size)

    for (i, src) in pair:
        assert (0 <= i <= i+len(src) <= size)
        dst[i:i+len(src)] = src

    return bytes(dst)


def rol64(value: int, n: int) -> int:
    assert (_INT64_MIN <= value <= _UINT64_MAX)
    assert (-63 <= n <= 63)
    value &= _UINT64_MAX

    if 0 <= n:
        value = (value << n) | (value >> (64-n))
    else:
        value = (value >> (-n)) | (value << (64+n))

    value &= _UINT64_MAX
    return value


def ror64(value: int, n: int) -> int:
    return rol64(value, -n)


_iota: Iterator[bytes] | None = None


def iota() -> bytes:
    from itertools import cycle
    from string import digits, ascii_letters

    global _iota
    if not _iota:
        _iota = cycle(c.encode() for c in digits+ascii_letters)

    return next(_iota)


def shstr(command: str) -> list[str]:
    from shlex import split
    return split(command)


_COLOR = dict(
    END='\033[0m',
    BOLD='\033[1m',
    UNDERLINE='\033[4m',
    REVERCE='\033[07m',
    INVISIBLE='\033[08m',
    BLACK='\033[30m',
    RED='\033[31m',
    GREEN='\033[32m',
    YELLOW='\033[33m',
    BLUE='\033[34m',
    PURPLE='\033[35m',
    CYAN='\033[36m',
    WHITE='\033[37m'
)


def peep(value: Any, peepfmt: str | None = None) -> Any:
    peepfmt = peepfmt if peepfmt is not None else Config.peepfmt

    from inspect import stack
    from ast import parse, unparse, walk, AST, Call

    caller = stack()[1]
    code = caller.code_context
    assert (code is not None)
    index = caller.index
    assert (index is not None)
    assert (index < len(code))
    line = code[index]

    positions = caller.positions
    assert (positions)
    col_offset = positions.col_offset
    assert (col_offset is not None)
    end_col_offset = positions.end_col_offset
    assert (end_col_offset is not None)
    lineno = positions.lineno
    assert (lineno is not None)
    end_lineno = positions.end_lineno
    assert (end_lineno is not None)
    assert (lineno == end_lineno)

    root = parse(line[col_offset:end_col_offset])
    args = []
    for node in walk(root):
        if isinstance(node, Call):
            args = node.args
            break
    assert (args)

    args = cast(AST, args)
    args = unparse(args)

    if peepfmt:
        message = peepfmt.format(lineno, args, value, **_COLOR)
        print(message)

    return value


def hexdump(format: str, data: bytes) -> Iterator[str]:
    from string import Formatter

    class HexDumpFormatter(Formatter):
        def format_field(self, value: Any, spec: str):
            match spec:
                case '!ul' | '!ub':
                    if value:
                        value = u64(value.ljust(8, b'\x00'), be=spec == '!ub')
                        value = f'{value:#x}'
                    else:
                        value = ''
                    spec = '>18s'

                case '!s':
                    value = [chr(i) for i in value]
                    for i in range(len(value)):
                        if not ' ' <= value[i] <= '~':
                            value[i] = '.'
                    value = ''.join(value)
                    spec = '8s'

                case '!b':
                    value = [f'{i:02x}' for i in value]
                    value = ' '.join(value)
                    spec = '23s'

            return super().format_field(value, spec)

    formatter = HexDumpFormatter()
    off = 0

    while data:
        fst, snd, data = data[:0x8], data[0x8:0x10], data[0x10:]
        yield formatter.format(format, off, fst, snd, **_COLOR)
        off += 0x10


class Logger:
    @staticmethod
    def send(fun):
        @wraps(fun)
        def log(self, data, *args, **kwargs):
            n = fun(self, data, *args, **kwargs)
            if Config.sendfmt:
                for line in hexdump(Config.sendfmt, data[:n]):
                    print(line)
            return n
        return log

    @staticmethod
    def recv(fun):
        @wraps(fun)
        def log(self, *args, **kwargs):
            data = fun(self, *args, **kwargs)
            if Config.recvfmt:
                for line in hexdump(Config.recvfmt, data):
                    print(line)
            return data
        return log


class Tube(metaclass=ABCMeta):
    @abstractmethod
    def _send(self, data: bytes) -> int:
        pass

    @abstractmethod
    def _recv(self, size: int) -> bytes:
        pass

    @abstractmethod
    def gettimeout(self) -> float | None:
        pass

    @abstractmethod
    def settimeout(self, timeout: float | None):
        pass

    def __init__(self):
        self._sbuf: bytes = b''
        self._rbuf: bytes = b''

    def send(self, data: bytes):
        if self._sbuf:
            data, self._sbuf = self._sbuf+data, b''

        try:
            while data:
                n = self._send(data)
                data = data[n:]

        except Exception as e:
            self._sbuf = data+self._sbuf
            raise e

    def sendline(self, data: bytes):
        self.send(data+b'\n')

    def recv(self, size: int = 0x1000) -> bytes:
        if self._rbuf:
            data, self._rbuf = self._rbuf[:size], self._rbuf[size:]
            return data

        return self._recv(size)

    def recvexact(self, n: int, size: int = 0x1000) -> bytes:
        data = b''

        try:
            while len(data) < n:
                data += self.recv(size=size)

        except Exception as e:
            self._rbuf = data+self._rbuf
            raise e

        data, rest = data[:n], data[n:]
        self._rbuf = rest+self._rbuf
        return data

    def recvuntil(self, delim: bytes, size: int = 0x1000) -> bytes:
        data = b''

        try:
            while (pos := data.find(delim)) == -1:
                data += self.recv(size=size)

        except Exception as e:
            self._rbuf = data+self._rbuf
            raise e

        pos += len(delim)
        data, rest = data[:pos], data[pos:]
        self._rbuf = rest+self._rbuf
        return data

    def recvline(self, size: int = 0x1000) -> bytes:
        return self.recvuntil(b'\n', size=size)

    def sendafter(self, delim: bytes, data: bytes, size: int = 0x1000) -> bytes:
        buf = self.recvuntil(delim, size=size)
        self.send(data)
        return buf

    def sendlineafter(self, delim: bytes, data: bytes, size: int = 0x1000) -> bytes:
        buf = self.recvuntil(delim, size=size)
        self.sendline(data)
        return buf

    def interactive(self, size: int = 0x1000):
        from select import epoll, EPOLLIN, EPOLLERR, EPOLLHUP
        from os import read, write
        from ssl import SSLWantReadError

        timeout = self.gettimeout()

        try:
            with epoll(1) as epollfd:
                epollfd.register(0, EPOLLIN)

                try:
                    while True:
                        try:
                            self.settimeout(0)
                            buf = self.recv(size)

                        except (BlockingIOError, SSLWantReadError):
                            pass

                        else:
                            while buf:
                                n = write(1, buf)
                                buf = buf[n:]

                        if ev := dict(epollfd.poll(0)):
                            def chkfd(fd: int, flag: int) -> bool:
                                return bool(ev.get(fd, 0) & flag)

                            if chkfd(0, EPOLLIN):
                                buf = read(0, size)
                                self.settimeout(None)
                                self.send(buf)

                            else:
                                assert (chkfd(0, EPOLLERR | EPOLLHUP))
                                raise BrokenPipeError

                except KeyboardInterrupt:
                    pass

        finally:
            self.settimeout(timeout)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Net:
    from socket import socket
    from ssl import SSLContext

    @staticmethod
    def noverify() -> SSLContext:
        from ssl import create_default_context, CERT_NONE
        context = create_default_context()
        context.check_hostname = False
        context.verify_mode = CERT_NONE
        return context

    @staticmethod
    def _socket(udp: bool, ipv6: bool, ssl: SSLContext | None) -> socket:
        from socket import socket, SOL_SOCKET, SO_REUSEADDR
        from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, IPPROTO_TCP, IPPROTO_UDP

        family = AF_INET if not ipv6 else AF_INET6
        type_ = SOCK_STREAM if not udp else SOCK_DGRAM
        proto = IPPROTO_TCP if not udp else IPPROTO_UDP

        sk = socket(family, type_, proto)

        try:
            sk.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

            if ssl:
                sk = ssl.wrap_socket(sk)

            return sk

        except Exception as e:
            sk.close()
            raise e


class Remote(Tube):
    from socket import socket
    from ssl import SSLContext

    @classmethod
    def run(cls,
            host: str, port: int,
            udp: bool = False,
            ipv6: bool = False,
            ssl: SSLContext | None = None) -> Self:

        sk = Net._socket(udp, ipv6, ssl)

        try:
            sk.connect((host, port))
            return cls(sk)

        except Exception as e:
            sk.close()
            raise e

    def __init__(self, sk: socket):
        from socket import socket
        super().__init__()
        self._sk: socket = sk

    @Logger.send
    def _send(self, data: bytes) -> int:
        return self._sk.send(data)

    @Logger.recv
    def _recv(self, size: int) -> bytes:
        return self._sk.recv(size)

    def gettimeout(self) -> float | None:
        return self._sk.gettimeout()

    def settimeout(self, timeout: float | None):
        self._sk.settimeout(timeout)

    def close(self):
        self._sk.close()


class ProcessMonitoringError(Exception):
    def __init__(self, status: int | None):
        from os import WIFEXITED, WEXITSTATUS
        from os import WIFSIGNALED, WTERMSIG
        from os import WIFSTOPPED, WSTOPSIG
        from os import WIFCONTINUED

        if status is None:
            message = f'process is terminated'

        elif WIFEXITED(status):
            reason = WEXITSTATUS(status)
            message = f'process exited with code {reason}'

        elif WIFSIGNALED(status):
            reason = WTERMSIG(status)
            message = f'process was killed by signal {reason}'

        elif WIFSTOPPED(status):
            reason = WSTOPSIG(status)
            message = f'process was stopped by signal {reason}'

        else:
            assert (WIFCONTINUED(status))
            message = f'process has been resumed'

        super().__init__(message)
        self.status: int | None = status


class ProcessManager:
    from subprocess import Popen

    def __init__(self, *proc: Popen):
        from subprocess import Popen
        self._proc: list[Popen] = list(proc)

    def move(self, *proc: Popen):
        self._proc += list(proc)

    def close(self):
        from subprocess import TimeoutExpired

        for p in self._proc:
            try:
                if p.poll() is not None:
                    p.terminate()
                p.wait(0.1)

            except TimeoutExpired:
                if p.poll() is not None:
                    p.kill()
                p.wait()


class AtExit:
    def __init__(self, command: list[str]):
        self._command: list[str] = command

    def __enter__(self):
        return self

    def __exit__(self, cls: Type, *_):
        from subprocess import run

        if issubclass(cls, ProcessMonitoringError):
            run(self._command)
            return True

        return False


class Debugger(metaclass=ABCMeta):
    @abstractmethod
    def attach(self, pid: int) -> list[str]:
        pass


class AttachProtocol(Protocol):
    @property
    def _manager(self) -> ProcessManager:
        ...

    @property
    def pid(self) -> int:
        ...

    @property
    def attached(self) -> bool:
        ...

    @attached.setter
    def attached(self, value: bool):
        ...


class Attach:
    def attach(self: AttachProtocol, debugger: Debugger):
        from subprocess import Popen
        from os import getenv
        from pdb import Pdb
        from inspect import currentframe

        if not self.attached:
            self.attached = True
            command = debugger.attach(self.pid)
            proc = Popen(command)
            self._manager.move(proc)

        if getenv('PYTHONBREAKPOINT'):
            breakpoint()

        else:
            pdb = Pdb()
            frame = currentframe()
            assert (frame)
            pdb.set_trace(frame.f_back)


class Process(Tube, Attach):
    from typing import BinaryIO

    @dataclass
    class Opt:
        tty: str
        env: dict[str, str]
        aslr: bool
        dbg: str
        script: str
        opt: list[str]
        term: list[str]

    _builder_: dict[str, Callable[[list[str], Opt], list[str]]] = {}

    @classmethod
    def dbg(cls, *name: str):
        def register(fun: Callable[[list[str], Process.Opt], list[str]]):
            cls._builder_.update(dict((i, fun) for i in name))
            return fun
        return register

    @classmethod
    def run(cls,
            command: list[str],
            env: dict[str, str] | None = None,
            aslr: bool | None = None,
            dbg: str | None = None,
            script: str | None = None,
            opt: list[str] | None = None,
            term: list[str] | None = None) -> Self:

        env = env if env is not None else Config.env
        aslr = aslr if aslr is not None else Config.aslr
        dbg = dbg if dbg is not None else Config.dbg
        script = script if script is not None else Config.script
        opt = opt if opt is not None else Config.opt
        term = term if term is not None else Config.term

        from pty import openpty
        from tty import setraw
        from fcntl import fcntl, F_GETFL, F_SETFL
        from os import ttyname, tcgetpgrp
        from os import fdopen, close, O_NONBLOCK
        from subprocess import Popen

        master, slave = openpty()

        try:
            setraw(master)
            fl = fcntl(master, F_GETFL)
            fcntl(master, F_SETFL, fl | O_NONBLOCK)
            tty = ttyname(slave)
            bio = fdopen(master, 'r+b', buffering=0)

        except Exception as e:
            close(master)
            raise e

        finally:
            close(slave)

        try:
            opt_ = cls.Opt(tty, env, aslr, dbg, script, opt, term)
            assert (dbg in cls._builder_)
            command = cls._builder_[opt_.dbg](command, opt_)
            proc = Popen(command)
            manager = ProcessManager(proc)

            try:
                while not (pid := tcgetpgrp(bio.fileno())):
                    pass

                child = pid == proc.pid
                self = cls(manager, bio, pid, child)
                self.attached = bool(dbg)

            except Exception as e:
                manager.close()
                raise e

        except Exception as e:
            bio.close()
            raise e

        return self

    def __init__(self, manager: ProcessManager, bio: BinaryIO, pid: int, child: bool):
        from typing import BinaryIO
        from os import pidfd_open, close
        from select import epoll, EPOLLIN

        super().__init__()
        pidfd = pidfd_open(pid)

        try:
            epollfd = epoll(2)

            try:
                epollfd.register(bio, 0)
                epollfd.register(pidfd, EPOLLIN)

            except Exception as e:
                epollfd.close()
                raise e

        except Exception as e:
            close(pidfd)
            raise e

        self._manager: ProcessManager = manager
        self.pid: int = pid
        self.attached: bool = False
        self._bio: BinaryIO = bio
        self._timeout: float | None = None
        self._pidfd: int = pidfd
        self._child: bool = child
        self._epollfd: epoll = epollfd

    @Logger.send
    def _send(self, data: bytes) -> int:
        if self._ready(True):
            n = self._bio.write(data)
            assert (n is not None)
            return n
        else:
            return 0

    @Logger.recv
    def _recv(self, size: int) -> bytes:
        if self._ready(False):
            data = self._bio.read(size)
            assert (data is not None)
            return data
        else:
            return b''

    def gettimeout(self) -> float | None:
        return self._timeout

    def settimeout(self, timeout: float | None):
        self._timeout = timeout

    def _ready(self, out: bool) -> bool:
        from select import EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP
        from os import waitid, P_PIDFD, WEXITED, WNOWAIT

        mask = EPOLLOUT if out else EPOLLIN
        self._epollfd.modify(self._bio, mask)
        biofd = self._bio.fileno()
        timeout = self.gettimeout()

        while ev := dict(self._epollfd.poll(timeout)):
            def chkfd(fd: int, flag: int) -> bool:
                return bool(ev.get(fd, 0) & flag)

            if chkfd(biofd, EPOLLIN):
                return True

            elif chkfd(self._pidfd, EPOLLIN):
                if self._child:
                    result = waitid(P_PIDFD, self._pidfd, WEXITED | WNOWAIT)
                    assert (result)
                    status = result.si_status
                else:
                    status = None

                raise ProcessMonitoringError(status)

            elif chkfd(biofd, EPOLLOUT):
                return True

            else:
                assert (chkfd(biofd, EPOLLERR | EPOLLHUP) or
                        chkfd(self._pidfd, EPOLLERR | EPOLLHUP))

        assert (timeout is not None)
        if not timeout:
            return False

        raise TimeoutError

    def close(self):
        from os import close
        self._manager.close()
        self._bio.close()
        close(self._pidfd)
        self._epollfd.close()


class Local(Remote, Attach):
    from socket import socket
    from ssl import SSLContext

    @classmethod
    def run(cls,
            host: str, port: int,
            udp: bool = False,
            ipv6: bool = False,
            ssl: SSLContext | None = None) -> Self:

        pid = cls.pidof(host, port, udp=udp, ipv6=ipv6)
        sk = Net._socket(udp, ipv6, ssl)

        try:
            sk.connect((host, port))
            manager = ProcessManager()
            return cls(manager, sk, pid)

        except Exception as e:
            sk.close()
            raise e

    @staticmethod
    def pidof(host: str, port: int,
              udp: bool = False,
              ipv6: bool = False) -> int:

        from glob import iglob
        from os import readlink
        from re import compile

        pidpat = compile(r'/proc/(\d+)/fd/\d+')
        inode = Local._inodeof(host, port, udp, ipv6)

        for i in iglob('/proc/*/fd/*'):
            if found := pidpat.fullmatch(i):
                pid = found.group(1)
                pid = int(pid)

                try:
                    if readlink(i) == f'socket:[{inode}]':
                        return pid

                except FileNotFoundError:
                    pass

        raise FileNotFoundError

    @staticmethod
    def _inodeof(host: str, port: int,
                 udp: bool,
                 ipv6: bool) -> int:

        from socket import getaddrinfo
        from ipaddress import ip_address
        from socket import socket, AF_NETLINK, SOCK_RAW
        from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, IPPROTO_TCP, IPPROTO_UDP
        from socket import htons
        from select import epoll, EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP
        from struct import pack, unpack_from, calcsize

        family = AF_INET if not ipv6 else AF_INET6
        type_ = SOCK_STREAM if not udp else SOCK_DGRAM
        proto = IPPROTO_TCP if not udp else IPPROTO_UDP

        addrinfo = getaddrinfo(host, port,
                               family=family, type=type_, proto=proto)
        addrs = set(i[-1][0] for i in addrinfo)
        addrs = set(ip_address(i).packed for i in addrs)

        nlmsghdr_fmt = 'I2H2I'
        inet_diag_sockid_fmt = '2H16s16s3I'
        inet_diag_req_v2_fmt = f'4BI{inet_diag_sockid_fmt}'
        inet_diag_msg_fmt = f'4B{inet_diag_sockid_fmt}5I'
        nlmsghdr_size = calcsize(nlmsghdr_fmt)
        inet_diag_req_v2_size = calcsize(inet_diag_req_v2_fmt)
        inet_diag_msg_size = calcsize(inet_diag_msg_fmt)

        NETLINK_SOCK_DIAG = 4
        SOCK_DIAG_BY_FAMILY = 20
        NLM_F_REQUEST = 0x01
        NLM_F_ROOT = 0x100
        NLM_F_MATCH = 0x200
        NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH
        TCP_LISTEN = 10
        NLMSG_DONE = 0x1
        NLMSG_ERROR = 0x2
        NLMSG_DONE = 0x3

        request = b''
        request += pack(nlmsghdr_fmt, *[
            nlmsghdr_size+inet_diag_req_v2_size,
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            0,
            0
        ])
        request += pack(inet_diag_req_v2_fmt, *[
            family,
            proto,
            0,
            0,
            1 << TCP_LISTEN if not udp else 0xffffffff,
            htons(port),
            0,
            b'\x00\x00\x00\x00'*4,
            b'\x00\x00\x00\x00'*4,
            0,
            0, 0
        ])

        with socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG) as sk:
            with epoll(1) as epollfd:
                epollfd.register(sk, EPOLLIN | EPOLLOUT)

                while ev := dict(epollfd.poll()):
                    def chkfd(fd: int, flag: int) -> bool:
                        return bool(ev.get(fd, 0) & flag)

                    if chkfd(sk.fileno(), EPOLLIN):
                        packet = sk.recv(0x2000)

                        while packet:
                            if len(packet) < nlmsghdr_size:
                                break

                            nlmsghdr = unpack_from(nlmsghdr_fmt, packet)

                            if not nlmsghdr_size <= nlmsghdr[0] <= len(packet):
                                break

                            if nlmsghdr[1] in [NLMSG_DONE, NLMSG_ERROR]:
                                break

                            if nlmsghdr[1] == SOCK_DIAG_BY_FAMILY:
                                if len(packet) < nlmsghdr_size+inet_diag_msg_size:
                                    break

                                inet_diag_msg = unpack_from(
                                    inet_diag_msg_fmt, packet, nlmsghdr_size)

                                if inet_diag_msg[0] != family:
                                    break

                                src = inet_diag_msg[6]
                                src = src[:4] if not ipv6 else src
                                inode = inet_diag_msg[15]

                                if not any(src) or src in addrs:
                                    return inode

                            def align(size: int) -> int:
                                return (size+3) & ~3

                            packet = packet[align(nlmsghdr[0]):]

                    elif chkfd(sk.fileno(), EPOLLOUT):
                        packet = request

                        while packet:
                            n = sk.send(packet)
                            packet = packet[n:]

                    else:
                        assert (chkfd(sk.fileno(), EPOLLERR | EPOLLHUP))
                        raise BrokenPipeError

        raise TimeoutError

    def __init__(self, manager: ProcessManager, sk: socket, pid: int):
        from os import pidfd_open, close
        from select import epoll, EPOLLIN

        super().__init__(sk)
        pidfd = pidfd_open(pid)

        try:
            epollfd = epoll(1)

            try:
                epollfd.register(pidfd, EPOLLIN)

            except Exception as e:
                epollfd.close()
                raise e

        except Exception as e:
            close(pidfd)
            raise e

        self._manager: ProcessManager = manager
        self.pid: int = pid
        self.attached: bool = False
        self._pidfd: int = pidfd
        self._epollfd: epoll = epollfd

    def _send(self, data: bytes) -> int:
        self._exited()
        return super()._send(data)

    def _recv(self, size: int) -> bytes:
        self._exited()
        return super()._recv(size)

    def _exited(self):
        from select import EPOLLIN, EPOLLERR, EPOLLHUP
        from os import waitid, P_PIDFD, WEXITED, WNOWAIT

        if ev := dict(self._epollfd.poll(0)):
            def chkfd(fd: int, flag: int) -> bool:
                return bool(ev.get(fd, 0) & flag)

            if chkfd(self._pidfd, EPOLLIN):
                try:
                    result = waitid(P_PIDFD, self._pidfd, WEXITED | WNOWAIT)
                    assert (result)
                    status = result.si_status

                except ChildProcessError:
                    status = None

                raise ProcessMonitoringError(status)

            else:
                assert (chkfd(self._pidfd, EPOLLERR | EPOLLHUP))

    def close(self):
        from os import close
        super().close()
        self._manager.close()
        close(self._pidfd)
        self._epollfd.close()


class NoDebugger:
    @Process.dbg('')
    @staticmethod
    def run(command: list[str], opt: Process.Opt) -> list[str]:
        from sys import executable

        inner_command = command
        command = [executable, __file__]

        if opt.tty:
            command = [*command, '-t', opt.tty]

        for (k, v) in opt.env.items():
            command += ['-e', f'{k}={v}']

        if not opt.aslr:
            command = [*command, '-d']

        command = [*command, '--', *inner_command]
        return command


class Gdb(Debugger):
    @Process.dbg('gdb', 'gdb-multiarch')
    @staticmethod
    def run(command: list[str], opt: Process.Opt) -> list[str]:
        inner_command = command
        command = [*opt.term, opt.dbg]

        if opt.tty:
            command = [*command, f'--tty={opt.tty}']

        for (k, v) in opt.env.items():
            command += ['-ex', f'set environment {k} {v}']

        if not opt.aslr:
            command = [*command, '-ex', 'set disable-randomization on']

        if opt.script:
            command = [*command, '-x', opt.script]

        command = [*command, *opt.opt, '--args', *inner_command]
        return command

    def __init__(self,
                 script: str | None = None,
                 opt: list[str] | None = None,
                 term: list[str] | None = None,
                 gdb: str | None = None):

        script = script if script is not None else Config.script
        opt = opt if opt is not None else Config.opt
        term = term if term is not None else Config.term
        gdb = gdb if gdb is not None else Config.gdb

        super().__init__()
        self.script: str = script
        self.opt: list[str] = opt
        self.term: list[str] = term
        self.gdb: str = gdb

    def attach(self, pid: int) -> list[str]:
        command = [*self.term, self.gdb, '-p', f'{pid}']

        if self.script:
            command = [*command, '-x', self.script]

        command = [*command, *self.opt]
        return command


class Rr:
    @Process.dbg('rr')
    @staticmethod
    def record(command: list[str], opt: Process.Opt) -> list[str]:
        from sys import executable

        inner_command = command
        command = [executable, __file__]

        if opt.tty:
            command = [*command, '-t', opt.tty]

        if not opt.aslr:
            command = [*command, '-d']

        command = [*command, '--', opt.dbg, 'record']

        for (k, v) in opt.env.items():
            command += ['-v', f'{k}={v}']

        command = [*command, *opt.opt, *inner_command]
        return command

    def __init__(self,
                 script: str | None = None,
                 opt: list[str] | None = None,
                 term: list[str] | None = None,
                 rr: str | None = None):

        script = script if script is not None else Config.script
        opt = opt if opt is not None else Config.opt
        term = term if term is not None else Config.term
        rr = rr if rr is not None else Config.rr

        self.script: str = script
        self.opt: list[str] = opt
        self.term: list[str] = term
        self.rr: str = rr

    def replay(self) -> list[str]:
        command = [*self.term, self.rr, 'replay']

        if self.script:
            command = [*command, '-x', self.script]

        command = [*command, *self.opt]
        return command

    @classmethod
    def atexit(cls) -> AtExit:
        return AtExit(cls().replay())


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-t', '--tty', default='')
    parser.add_argument('-e', '--env', action='append', default=[])
    parser.add_argument('-d', '--disable-randomization',
                        action='store_true', default=False)
    parser.add_argument('command', nargs='+')
    args = parser.parse_args()

    tty = args.tty
    env = (i.partition('=') for i in args.env)
    env = dict((i, j) for (i, _, j) in env)
    aslr = not args.disable_randomization
    command = args.command

    exec_command(command, tty, env, aslr)


def exec_command(command: list[str], tty: str, env: dict[str, str], aslr: bool):
    def wsl() -> bool:
        from platform import uname
        return 'microsoft-standard' in uname().release

    if tty:
        from os import setsid, getsid, setpgid
        from os import open, close, O_RDWR, O_NOCTTY
        from os import dup2
        from os import ctermid
        from tty import setraw
        from fcntl import ioctl
        from termios import TIOCNOTTY, TIOCSCTTY
        from signal import signal, SIG_IGN, SIGHUP, SIGCONT
        from contextlib import contextmanager

        @contextmanager
        def sigign(num: int) -> Iterator[Any]:
            handler = signal(num, SIG_IGN)

            try:
                yield handler
            finally:
                signal(num, handler)

        try:
            try:
                setpgid(0, getsid(0))
            except PermissionError:
                pass

            setsid()

        except PermissionError:
            fd = open(ctermid(), O_RDWR | O_NOCTTY)

            try:
                with sigign(SIGHUP), sigign(SIGCONT):
                    ioctl(fd, TIOCNOTTY, 0)
            finally:
                close(fd)

        fd = open(tty, O_RDWR | O_NOCTTY)

        try:
            setraw(fd)
            ioctl(fd, TIOCSCTTY, 0)
            dup2(fd, 0)
            dup2(fd, 1)
            dup2(fd, 2)
        finally:
            close(fd)

    def oserror():
        from ctypes import get_errno
        from os import strerror
        errno = get_errno()
        raise OSError(errno, strerror(errno))

    if not aslr:
        from ctypes import CDLL, c_int, c_ulong

        personality = CDLL(None).personality
        personality.restype = c_int
        personality.argtypes = [c_ulong]
        ADDR_NO_RANDOMIZE = 0x00040000

        if (persona := personality(0xffffffff)) == -1:
            oserror()

        if not persona & ADDR_NO_RANDOMIZE:
            if personality(persona | ADDR_NO_RANDOMIZE) == -1:
                oserror()

    if not wsl():
        from ctypes import CDLL, c_int, c_ulong

        prctl = CDLL(None).prctl
        prctl.restype = c_int
        prctl.argtypes = [c_int, c_ulong, c_ulong, c_ulong, c_ulong]
        PR_SET_PTRACER = 0x59616d61
        PR_SET_PTRACER_ANY = -1

        if prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0, 0) == -1:
            oserror()

    from os import environ, execlp

    environ.update(env)
    execlp(command[0], *command)


if __name__ == '__main__':
    main()
else:
    Config.init()
