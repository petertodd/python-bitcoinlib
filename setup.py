#!/usr/bin/env python

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README')) as f:
    README = f.read()

requires = []

setup(name='python-bitcoinlib',
      version='0.2.2-SNAPSHOT',
      description='This python library provides an easy interface to the Bitcoin data structures and protocol.',
      long_description=README,
      classifiers=[
          "Programming Language :: Python",
      ],
      url='https://github.com/petertodd/python-bitcoinlib',
      keywords='bitcoin',
      packages=find_packages(),
      zip_safe=False,
      install_requires=requires,
      test_suite="bitcoin.tests"
     )
