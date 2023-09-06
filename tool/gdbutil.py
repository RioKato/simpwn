# type: ignore

from gdb import Command
from typing import Iterator, cast
from re import Pattern


class Label(Command):
    @staticmethod
    def collect(command: str, pattern: Pattern[str]) -> Iterator[tuple[str, int]]:
        from gdb import execute

        result = execute(command, False, True)
        assert (result)

        for i in result.splitlines():
            if found := pattern.search(i):
                addr, label = found.groups()
                addr = int(addr, 16)
                label = cast(str, label)
                yield (label, addr)

            else:
                print(f'skip ... {i}')

    @staticmethod
    def msymbols() -> dict[str, int]:
        from re import compile
        command = 'maintenance print msymbols'
        pattern = r'(0x[0-9a-f]+)\s+(\S+)'
        pattern = compile(pattern)
        return dict(Label.collect(command, pattern))

    @staticmethod
    def mappings() -> dict[str, int]:
        from re import compile
        from os.path import basename
        command = 'info proc mappings'
        pattern = r'(0x[0-9a-f]+).*0x0\s+\S+\s+(\S+)'
        pattern = compile(pattern)
        return dict((f'base_{basename(k)}', v) for (k, v) in Label.collect(command, pattern))

    @staticmethod
    def files() -> dict[str, int]:
        from re import compile
        command = 'info files'
        pattern = r'(0x[0-9a-f]+).*is\s+(\S+)'
        pattern = compile(pattern)
        return dict(Label.collect(command, pattern))

    @staticmethod
    def sanitize(unsafe: bytes) -> bytes:
        from re import compile
        pattern = r'[^0-9a-zA-Z_]'
        pattern = compile(pattern)
        safe = pattern.sub('_', unsafe)
        safe = f'L_{safe}'
        return safe

    def __init__(self):
        from gdb import COMMAND_USER
        super().__init__('label', COMMAND_USER)

    def invoke(self, arg: str, _):
        from gdb import string_to_argv
        arg = string_to_argv(arg)
        out = arg[0]

        result = {}
        result.update(self.msymbols())
        result.update(self.mappings())
        result.update(self.files())
        result = dict((self.sanitize(k), v) for (k, v) in result.items())
        result = list(result.items())
        result.sort(key=lambda e: e[1])

        with open(out, 'w') as fd:
            for (k, v) in result:
                fd.write(f'{k} = {v:#018x}\n')


class DumpOff(Command):
    @ staticmethod
    def type(name: str):
        from gdb import execute, lookup_type
        from re import compile

        size = lookup_type('void').pointer().sizeof
        code = execute(f'maintenance print type {name}', False, True)
        assert (code)
        pattern = compile(r'bitpos\s+(\d+).*name\s*\'(\S*?)\'')

        result = {}
        for i in code.splitlines():
            if found := pattern.search(i):
                off = found.group(1)
                off = int(off)//size
                name = found.group(2)
                if name == '<NULL>':
                    continue
                result[name] = off

        return result

    def __init__(self):
        from gdb import COMMAND_USER
        super().__init__('dumpoff', COMMAND_USER)

    def invoke(self, arg: str, _):
        from gdb import string_to_argv
        arg = string_to_argv(arg)
        name = arg[0]
        out = arg[1]

        result = self.type(name)

        with open(out, 'w') as fd:
            for (k, v) in result.items():
                fd.write(f'{k} = {v:#x}\n')


def main():
    Label()
    DumpOff()


if __name__ == '__main__':
    main()
