#!/usr/bin/env python
import click
from flask import Flask
from flask.cli import FlaskGroup
from ca.application import app

def create_app():
    #app = Flask('MinaCA')
    # other setup
    return app

@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """Management script for the Wiki application."""

@cli.command()
def mina():
    """MinaCA"""
    
if __name__ == "__main__":
    cli()
