#!/usr/bin/env python
import click
from flask import Flask
from flask.cli import FlaskGroup
from ca.application import app


def create_app():
    # app = Flask('MinaCA')
    # other setup
    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """Management script for the Wiki application."""


@cli.command()
def mina():
    """MinaCA"""


@cli.command()
def initdb():
    """MinaCA DB Init"""
    from ca.database import init_db
    init_db()

    click.echo('DB가 생성되었습니다')


@cli.command()
def calc_line():
    import os
    import stat

    wc = 0
    size = 0

    def file_wc(path):
        with open(path, 'rb') as file_obj:
            return len(file_obj.readlines())

    def file_size(path):
        return os.stat(path)[stat.ST_SIZE]

    for root, dirs, files in os.walk("."):
        for entry in files:
            last_path = os.path.join(root, entry)
            if 'ca' in last_path:
                if 'ca/static' in last_path:
                    continue
                elif 'CA_ROOT' in last_path:
                    continue

                wc += file_wc(last_path)
                size += file_size(last_path)
            elif 'migration' in last_path:
                continue

    wc += len(open('.gitignore', 'r').readlines())
    wc += len(open('manage.py', 'r').readlines())

    click.echo('현재까지 {0:#,} 줄을 작성하셨습니다. 분발하셔야 하겠어요'.format(wc))
    click.echo('현재까지 {0:#,} 용량을 작성하셨습니다. 분발하셔야 하겠어요'.format(size))


if __name__ == "__main__":
    cli()
