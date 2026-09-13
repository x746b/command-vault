import os
from pathlib import Path


def get_config():
    dirs = {name: str(Path(os.environ[key]).expanduser().resolve())
            for name, key in [('unified','WRITEUPS'),('boxes','WRITEUPS_BOXES'),
                              ('challenges','WRITEUPS_CHALLENGES'),('sherlocks','WRITEUPS_SHERLOCKS')]
            if os.environ.get(key)}
    default = Path.home() / 'writeups'
    if not dirs and default.is_dir():
        dirs['unified'] = str(default)
    research_dir = None
    if os.environ.get('WRITEUPS_RESEARCH'):
        research_path = Path(os.environ['WRITEUPS_RESEARCH']).expanduser().absolute()
        if any(component.is_symlink() for component in (research_path, *research_path.parents)):
            raise ValueError('Configured research directory must not contain symlinks')
        research_dir = str(research_path.resolve())
    elif 'unified' in dirs:
        # Managed imports use the canonical nested layout. Autodetection keeps
        # ordinary `WRITEUPS=... vault index --add` safe even when a caller
        # does not repeat WRITEUPS_RESEARCH in that process environment.
        nested = Path(dirs['unified']) / 'research'
        if os.path.lexists(nested):
            if any(component.is_symlink() for component in (nested, *nested.parents)):
                raise ValueError('Configured research directory must not contain symlinks')
            if nested.is_dir():
                research_dir = str(nested.resolve())
    return {'db_path': str(Path(os.environ.get('VAULT_DB', str(Path.home()/'.local/share/command-vault/vault.db'))).expanduser()),
            'writeup_dirs': dirs, 'research_dir': research_dir}
