from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='kosty',
    version='1.6.4',
    author='Yassir Kachri',
    author_email='yassir@kosty.cloud',
    description='AWS Cost Optimization & Security Audit CLI Tool - Identify cost waste, security vulnerabilities, and compliance issues across 16 core AWS services',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/kosty-cloud/kosty',
    project_urls={
        'Bug Reports': 'https://github.com/kosty-cloud/kosty/issues',
        'Source': 'https://github.com/kosty-cloud/kosty',
        'Documentation': 'https://github.com/kosty-cloud/kosty/blob/main/docs/DOCUMENTATION.md',
    },
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    keywords='aws cost optimization security audit cloud infrastructure compliance finops devops',
    install_requires=[
        'click>=8.0.0',
        'boto3>=1.26.0',
    ],
    entry_points={
        'console_scripts': [
            'kosty=kosty.cli:cli',
        ],
    },
    python_requires='>=3.7',
    include_package_data=True,
    zip_safe=False,
)