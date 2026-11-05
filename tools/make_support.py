"""Small cross-platform filesystem operations used only by this repository's Makefile.

Copyright (c) 2026 Hayk Jomardyan - Lolisoft. Existing repository license applies.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OWNED = ('reports', '.pytest_cache', 'dist', '__pycache__', 'common/__pycache__', 'tests/__pycache__', 'ci/__pycache__')


def inside(value):
    path = Path(value)
    path = path if path.is_absolute() else ROOT / path
    resolved = path.resolve()
    if resolved == ROOT or ROOT not in resolved.parents:
        raise ValueError('Path must stay below the repository: ' + str(value))
    for ancestor in (path, *path.parents):
        if ancestor == ROOT:
            break
        if ancestor.is_symlink() or getattr(ancestor, 'is_junction', lambda: False)():
            raise ValueError('Refusing a symlink/junction path: ' + str(value))
    return resolved


def output(value):
    path = inside(value)
    relative = path.relative_to(ROOT).as_posix()
    if not any(relative == name or relative.startswith(name + '/') for name in OWNED):
        raise ValueError('Not an owned Makefile output: ' + relative)
    return path


def clean(paths):
    # Check every requested target before deleting anything. Tracked files are source.
    targets = [output(value) for value in paths]
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    for target in targets:
        prefix = target.relative_to(ROOT).as_posix()
        if any(name == prefix or name.startswith(prefix + '/') for name in tracked):
            raise ValueError('Refusing to remove tracked source: ' + prefix)
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['help', 'clean', 'mkdir', 'source-zip', 'tree-zip', 'copy-package', 'version', 'require'])
    parser.add_argument('paths', nargs='*')
    args = parser.parse_args()
    if args.action == 'help':
        print('Usage: make TARGET [TOOL=/path/to/executable]')
        for line in (ROOT / 'Makefile').read_text(encoding='utf-8').splitlines():
            match = re.match(r'^([A-Za-z0-9][A-Za-z0-9_-]*):.*?##\s*(.+)$', line)
            if match:
                print('  {:24s} {}'.format(*match.groups()))
    elif args.action == 'clean':
        if not args.paths:
            parser.error('clean requires explicit output paths')
        clean(args.paths)
    elif args.action == 'mkdir':
        for value in args.paths:
            output(value).mkdir(parents=True, exist_ok=True)
    elif args.action == 'source-zip':
        if len(args.paths) != 1:
            parser.error('source-zip requires an output ZIP path')
        target = output(args.paths[0])
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'archive', '--format=zip', '--output=' + str(target), 'HEAD'], cwd=ROOT, check=True)
    elif args.action == 'tree-zip':
        if len(args.paths) != 2:
            parser.error('tree-zip requires a generated directory and an output ZIP path')
        tree, target = output(args.paths[0]), output(args.paths[1])
        if not tree.is_dir() or not any(tree.iterdir()):
            raise ValueError('Build output is missing/empty: ' + str(tree))
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as archive:
            for source in sorted(tree.rglob('*')):
                if source.is_symlink() or getattr(source, 'is_junction', lambda: False)():
                    raise ValueError('Refusing a symlink in build output')
                if source.is_file():
                    archive.write(source, source.relative_to(tree).as_posix())
        with zipfile.ZipFile(target) as archive:
            if archive.testzip() is not None:
                raise ValueError('ZIP CRC verification failed')
    elif args.action == 'copy-package':
        if len(args.paths) != 1:
            parser.error('copy-package requires a destination ZIP path')
        manifest = json.loads((ROOT / 'release/wordpress-upload.json').read_text())
        archive_name = manifest['archive']
        if Path(archive_name).name != archive_name:
            raise ValueError('Manifest archive must be a filename below release/')
        source = inside('release/' + archive_name)
        target = output(args.paths[0])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    elif args.action == 'version':
        if len(args.paths) != 1:
            parser.error('version requires a plugin entry file')
        text = inside(args.paths[0]).read_text(encoding='utf-8')
        match = re.search(r'^\s*\*\s*Version:\s*(\S+)', text, re.M)
        if not match:
            raise ValueError('Plugin version header is missing')
        print(match.group(1))
    elif args.action == 'require':
        for value in args.paths:
            if not inside(value).exists():
                raise ValueError('Required input is missing: ' + value + '; run the matching install target')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
