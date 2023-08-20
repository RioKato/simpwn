from requests import Session
from re import compile


def gencode(name: str, table: dict[str, int]) -> str:
    table_ = list(table.items())
    table_.sort(key=lambda e: e[1])
    code = f'class {name}:\n'
    for (k, v) in table_:
        code += f'    {k} = {v}\n'
    return code


def syscall_table(url: str) -> dict[str, int]:
    with Session() as s:
        response = s.get(url)
        text = response.text

    table = {}
    pattern = compile(r'(\d+).*sys_(\S+)')
    for i in text.splitlines():
        if found := pattern.match(i):
            num = found.group(1)
            num = int(num)
            name = found.group(2)
            name = name.upper()
            table[name] = num
        else:
            print(f'skipped ... {i}')

    return table


def uapi(url: str) -> dict[str, int]:
    with Session() as s:
        response = s.get(url)
        text = response.text

    table = {}
    pattern = compile(r'#define\s+__NR_(\S+)\s+(\d+)')
    for i in text.splitlines():
        if found := pattern.match(i):
            num = found.group(2)
            num = int(num)
            name = found.group(1)
            name = name.upper()
            table[name] = num
        else:
            print(f'skipped ... {i}')

    return table


def main():
    code = ''

    URL_X86 = 'https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_32.tbl'
    URL_X64 = 'https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl'
    URL_ARM32 = 'https://raw.githubusercontent.com/torvalds/linux/master/arch/arm/tools/syscall.tbl'

    for (i, j) in [('X86', URL_X86), ('X64', URL_X64), ('ARM32', URL_ARM32)]:
        table = syscall_table(j)
        code += gencode(i, table)
        code += '\n\n'

    URL_UAPI = 'https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h'
    table = uapi(URL_UAPI)
    code += gencode('ARM64', table)

    with open('syscall.py', 'w') as fd:
        fd.write(code)


main()
