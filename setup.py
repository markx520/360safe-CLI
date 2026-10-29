#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="360safe-cli",
    version="1.0.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "psutil>=5.8.0",
    ],
    entry_points={
        "console_scripts": [
            "360=qihoo360_cli.cli:main",
            "360-cli=qihoo360_cli.cli:main",
            "360safe-cli=qihoo360_cli.cli:main",
        ],
    },
)
