#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import setup


def read_(file_name):
    return open(os.path.join(os.path.dirname(__file__), file_name)).read()


setup(
    name="utinyec",
    version="0.4.2",
    packages=["utinyec"],
    author="Jack Lawrence",
    author_email="JackLawrenceCRISPR@gmail.com",
    description=(
        "A tiny library to perform potentially unsafe cryptography with arithmetic operations on elliptic curves in pure micropython."),
    license="aGPLv3",
    keywords=["elliptic", "curves", "crypto", "tls", "ssl", "ecdhe", "diffie-hellman"],
    url="https://github.com/JackLawrenceCRISPR/utinyec",
    long_description=read_("README.md"),
    long_description_content_type="text/markdown",
    classifiers=["Programming Language :: Python :: Implementation :: MicroPython"]
)
