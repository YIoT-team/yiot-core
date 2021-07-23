from yiot_trust_provisioner import __version__, __author__
from setuptools import setup, find_packages

setup(
    name="yiot_trust_provisioner",
    version=__version__,
    packages=find_packages(exclude=('tests',)),
    install_requires=[
        'virgil-sdk==5.2.1',
        'virgil-crypto>=3,<4',
        'prettytable',
        'pyasn1',
        'psutil',
        'tinydb'
    ],
    entry_points={
        'console_scripts':
            [
                'yiot-trust-provisioner = yiot_trust_provisioner.__main__:main'
            ]
    },
    author=__author__,
    author_email="support@yiot-dev.io",
    url="https://yiot-dev.io/",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.5",
        "Topic :: Security :: Cryptography",
        ],
    license="BSD",
    description="Yiot Trust Provisioner cli",
    long_description="Yiot Trust Provisioner cli",
)
