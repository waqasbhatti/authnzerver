# -*- coding: utf-8 -*-

'''This sets up the package.

Stolen from http://python-packaging.readthedocs.io/en/latest/everything.html and
modified by me.

'''

import versioneer
__version__ = versioneer.get_version()

from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


# let's be lazy and put requirements in one place
# what could possibly go wrong?
with open('requirements.txt') as infd:
    INSTALL_REQUIRES = [x.strip('\n') for x in infd.readlines()]

cmdclass = versioneer.get_cmdclass()

###############
## RUN SETUP ##
###############

setup(
    name='authnzerver',
    version=__version__,
    cmdclass=cmdclass,
    description=('A small authentication-authorization server.'),
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    keywords='authentication authorization tornado',
    url='https://github.com/waqasbhatti/authnzerver',
    author='Waqas Bhatti',
    author_email='waqas.afzal.bhatti@gmail.com',
    license='MIT',
    packages=find_packages(),
    install_requires=INSTALL_REQUIRES,
    entry_points={
        'console_scripts':[
            'authnzrv=authnzerver.main:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.6',
)
