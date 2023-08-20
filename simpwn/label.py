from pathlib import Path
OUTFILE: str = str(Path(__file__).parent.joinpath('label.json'))

try:
    from gdb import Command
    from typing import Iterator, cast
    from re import Pattern

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

    class Collector(Command):
        @staticmethod
        def msymbols() -> dict[str, int]:
            from re import compile

            command = 'maintenance print msymbols'
            pattern = r'(0x[0-9a-f]+)\s+(\S+)'
            pattern = compile(pattern)
            return dict(collect(command, pattern))

        @staticmethod
        def mappings() -> dict[str, int]:
            from re import compile

            command = 'info proc mappings'
            pattern = r'(0x[0-9a-f]+).*0x0\s+\S+\s+(.*)'
            pattern = compile(pattern)
            return dict((f'base of {k}', v) for (k, v) in collect(command, pattern))

        @staticmethod
        def files() -> dict[str, int]:
            from re import compile

            command = 'info files'
            pattern = r'(0x[0-9a-f]+).*is\s+(.*)'
            pattern = compile(pattern)
            return dict(collect(command, pattern))

        def __init__(self):
            from gdb import COMMAND_USER
            super().__init__('label', COMMAND_USER)

        def invoke(self, arg: str, _):
            if not arg:
                arg = OUTFILE

            from json import dump

            temp = {}
            temp.update(Collector.msymbols())
            temp.update(Collector.mappings())
            temp.update(Collector.files())

            with open(arg, 'w') as fd:
                dump(temp, fd)

    Collector()

except ImportError:
    class Label:
        def __init__(self, path: str = OUTFILE):
            from json import load

            try:
                with open(path) as fd:
                    data = load(fd)
            except FileNotFoundError:
                data = {}

            for (k, v) in data.items():
                setattr(self, k, v)

        def __getitem__(self, key: str) -> int:
            return getattr(self, key)

        def __setitem__(self, key: str, value: int):
            setattr(self, key, value)

        def search(self, *word: str) -> int:
            result = {}
            for k in dir(self):
                if all(i in k for i in word):
                    result[k] = self[k]

            match len(result):
                case 0:
                    print('search result does not exist')

                case 1:
                    return result.popitem()[1]

                case _:
                    print('there are multiple search results')

                    for (k, v) in result.items():
                        print(f'  {k} = {v:#018x}')

            raise ValueError
