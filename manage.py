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


if __name__ == "__main__":
    cli()
