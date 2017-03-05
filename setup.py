#!/usr/bin/env python

from setuptools import setup, find_packages
import os
import subprocess

from bitcoin import __version__

here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.md')
try:
    args = 'pandoc', '--from', 'markdown', '--to', 'rst', readme_path
    readme = subprocess.check_output(args).decode()
except Exception as error:
    print('README.md conversion to reStructuredText failed. Error:')
    print(error)
    with open(readme_path) as read_file:
        readme = read_file.read()

requires = []

setup(name='python-bitcoinlib',
      version=__version__,
      description='The Swiss Army Knife of the Bitcoin protocol.',
      long_description=readme,
      classifiers=[
          "Programming Language :: Python",
          "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
      ],
      url='https://github.com/petertodd/python-bitcoinlib',
      keywords='bitcoin',
      packages=find_packages(),
      zip_safe=False,
      install_requires=requires,
      test_suite="bitcoin.tests"
     )
