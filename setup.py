from pathlib import Path
from setuptools import find_packages, setup

this_directory = Path(__file__).parent
readme_path = this_directory / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="netpulse",
    version="1.0.0",
    description="Advanced CLI TCP/UDP Port Scanner with Async Engine, Raw SYN Stealth Scanning, Service Detection & Vulnerability Auditing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Professional Security Toolkit",
    url="https://github.com/example/netpulse",
    packages=find_packages(),
    py_modules=["main"],
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "rich>=10.0.0",
        "colorama>=0.4.4",
        "scapy>=2.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "netpulse=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
