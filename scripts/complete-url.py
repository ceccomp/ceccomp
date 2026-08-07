#!/usr/bin/python3
import re
import sys
import os

CHANGELOG = 'CHANGELOG.md'
DEFAULT_REPO = 'ceccomp/ceccomp'

# match 3 raw ref case：#123, !456, user/repo#789, user/repo!456
pattern = re.compile(r'(?:\s+)((?:[\w.-]+/[\w.-]+)?[#!]\d+)$')
# match '@username '
user_pat = re.compile(r'@([a-zA-Z0-9_-]+) ')


def convert(token: str) -> str:
    """Convert raw ref to URL"""
    repo = DEFAULT_REPO

    if '#' in token:
        if '/' in token.split('#')[0]:
            repo, number = token.split('#', 1)
        else:
            number = token[1:]
        return f'https://github.com/{repo}/issues/{number}'

    if '!' in token:
        if '/' in token.split('!')[0]:
            repo, number = token.split('!', 1)
        else:
            number = token[1:]
        return f'https://github.com/{repo}/pulls/{number}'

    assert False, f'Token {token} does not match any case, what the hack?'

def flush_refs(output_lines: list[str], refs: dict[str, str], need_lf: bool):
    """Write refs at the end of paragraph"""
    if refs:
        if need_lf:
            output_lines.append('\n') # terminate list
        output_lines.extend(f'[{token}]: {url}\n' for token, url in refs.items())
        refs.clear()


def main():
    if not os.path.isdir('.git'):
        print('Please goto repo root first', file=sys.stderr)
        sys.exit(2)
    is_check = len(sys.argv) > 1 and sys.argv[1] == '--check'
    has_match = False

    with open(CHANGELOG) as f:
        lines = f.readlines()

    refs = {} # token:url
    output_lines = []
    has_old_ref = False
    for lineno, line in enumerate(lines, start=1):
        if line.startswith('##'):
            flush_refs(output_lines, refs, not has_old_ref)
            has_old_ref = False
        elif line.startswith('['):
            has_old_ref = True

        # look for @user in line, NOT AT LINE END!
        mu = user_pat.search(line)
        if mu:
            user = mu.group(1)
            url = f'https://github.com/{user}'
            refs[f'@{user}'] = url
            line = line.replace(mu.group(0), f':heart: [@{user}] ')
            if is_check:
                print(f'[line {lineno}] found: {user}')
                has_match = True

        m = pattern.search(line)
        if m:
            token = m.group(1)
            url = convert(token)
            refs[token] = url
            new_line = line[: m.start(1)].rstrip() + f' :link: [{token}]\n'

            if is_check:
                print(f'[line {lineno}] found: {token}')
                has_match = True
            else:
                output_lines.append(new_line)
        elif not is_check:
            output_lines.append(line)

    # flush at EOF
    flush_refs(output_lines, refs, not has_old_ref)

    if not is_check:
        with open(CHANGELOG, 'w') as f:
            f.writelines(output_lines)

    # set exit code to 1 when see convertible ref in check mode
    if is_check and has_match:
        sys.exit(1)


if __name__ == '__main__':
    main()
