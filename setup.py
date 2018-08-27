from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst')) as f:
    long_description = f.read()

setup(
    name='libtf',
    version='0.1.1',
    license='MIT',
    author='Threshing Floor Security, LLC',
    author_email='info@threshingfloor.io',
    description='Threshing Floor python module for analyzing and reducing noise from log files.',
    long_description=long_description,
    packages=['libtf', 'libtf.logparsers'],
    py_modules=['libtf'],
    install_requires=['pytz', 'python-dateutil>=2,<3', 'requests>=2,<3', 'six'],
    url='https://github.com/ThreshingFloor/libtf',
    classifiers=['Development Status :: 3 - Alpha'],
)
