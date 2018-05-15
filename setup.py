#!/usr/bin/env python

from setuptools import setup, find_packages
import os

from bitcoin import __version__

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

requires = []

setup(name='python-altcoinlib',
      version=__version__,
      description='The Swiss Army Knife of the Bitcoin protocol with support for Bitcoin-based networks.',
      long_description=README,
      classifiers=[
          "Programming Language :: Python",
          "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
      ],
      url='https://github.com/Lamden/python-altcoinlib',
      keywords='bitcoin',
      packages=find_packages(),
      zip_safe=False,
      install_requires=requires,
      test_suite="bitcoin.tests"
     )
