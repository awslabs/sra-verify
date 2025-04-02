from setuptools import setup, find_packages

# Ensure all Python modules are included
packages = find_packages()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sraverify",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A security assessment tool for AWS infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/sraverify",
    packages=packages,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.26.0",
        "click>=8.0.0",
        "colorama>=0.4.4",
        "tabulate>=0.8.9"
    ],
    entry_points={
        "console_scripts": [
            "sraverify=sraverify.main:main"
        ]
    }
)