from setuptools import setup
from os import path

def load_dependencies():
    with open('requirements.txt') as dependencies:
            return dependencies.read().splitlines()

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst')) as f:
    long_description = f.read()

setup(
    name='tf-reaper',
    version = '0.0.1',
    license = 'MIT',
    author = 'Threshing Floor Security, LLC',
    author_email = 'info@threshingfloor.io',
    description = 'Threshing Floor python modules for analyzing and reducing noise from log files.',
    long_description = long_description,
    packages = ['libtf', 'libtf.logparsers'],
    data_files = [('requirements', ['requirements.txt'])],
    py_modules = ['libtf'],
    install_requires = load_dependencies(),
    url = 'https://github.com/ThreshingFloor/cli.reaper.threshingfloor.io',
    classifiers = ['Development Status :: 3 - Alpha'],
    )
