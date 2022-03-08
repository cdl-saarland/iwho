#!/usr/bin/env python3

import pathlib
import setuptools
from setuptools.command.develop import develop
from setuptools.command.install import install

import shutil
import sys

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()
LICENSE = (HERE / "LICENSE").read_text()

def post_command(a):
    # TODO extract the insn schemes here
    pass

class PostDevelopCommand(develop):
    def run(self):
        develop.run(self)
        post_command(self)

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        post_command(self)


setuptools.setup(
    name="iwho",
    version="0.0.1",
    description="IWHo: Instructions With Holes",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Fabian Ritter",
    author_email="fabian.ritter@cs.uni-saarland.de",
    license=LICENSE,
    packages=setuptools.find_packages(exclude=('tests',)),
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand,
    },
    install_requires=[
        "pyparsing",
        "rpyc",
    ],
    scripts=["tool/iwho-predict"],
    python_requires=">=3",
)
