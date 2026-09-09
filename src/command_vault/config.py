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
    return {'db_path': str(Path(os.environ.get('VAULT_DB', str(Path.home()/'.local/share/command-vault/vault.db'))).expanduser()),
            'writeup_dirs': dirs}
