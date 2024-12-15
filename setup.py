#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import setup

def read_(file_name):
    return open(os.path.join(os.path.dirname(__file__), file_name)).read()

setup(
    name="utinyec",
    version="0.4.5",
    packages=["utinyec"],
    requires=["base64","hmac"],
    author="Jack Lawrence",
    author_email="JackLawrenceCRISPR@gmail.com",
    description=(
        "A tiny library to perform unverified elliptic curve cryptography (ECC) with arithmetic operations in pure micropython. Not security verified for production."),
    license="aGPLv3",
    keywords=["elliptic", "curves", "crypto", "tls", "ssl", "ecdhe", "diffie-hellman"],
    url="https://github.com/JackLawrenceCRISPR/utinyec",
    long_description=read_("README.md"),
    long_description_content_type="text/markdown",
    classifiers=["Programming Language :: Python :: Implementation :: MicroPython"]
)
