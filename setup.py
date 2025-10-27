from setuptools import setup, find_packages

setup(
    name='kosty',
    version='1.2.0',
    packages=find_packages(),
    install_requires=[
        'click>=8.0.0',
        'boto3>=1.26.0',
        'asyncio'
    ],
    entry_points={
        'console_scripts': [
            'kosty=kosty.cli:cli',
        ],
    },
    author='Your Name',
    description='AWS Cost Optimization CLI Tool',
    python_requires='>=3.7',
)