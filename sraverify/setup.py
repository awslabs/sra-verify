from setuptools import setup, find_packages

# Ensure all Python modules are included
packages = find_packages()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sraverify",
    version="0.1.3",
    author="SRA Verify team",
    author_email="schiefj@amazon.com",
    description="AWS Security Reference Architecture Verification Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/awslabs/sra-verify",
    packages=packages,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.26.0",
        "colorama>=0.4.4"
    ],
    entry_points={
        "console_scripts": [
            "sraverify=sraverify.main:main"
        ]
    }
)