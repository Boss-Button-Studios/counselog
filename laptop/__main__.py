"""Entry point for `./counselog`. Command definitions live in laptop/cli.py."""

from laptop.cli import cli

if __name__ == "__main__":
    # prog_name so help and errors say `counselog`, not `python -m laptop`.
    cli(prog_name="counselog")
