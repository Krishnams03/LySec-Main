"""
DFTool - Digital Forensics Monitoring Daemon for Linux
Setup script for installation.
"""

from setuptools import setup, find_packages

setup(
    name="dftool",
    version="1.0.0",
    description="Linux Digital Forensics Monitoring Daemon - Detect, Log, Alert (No Prevention)",
    author="DFTool Team",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "pyudev>=0.24.0",
        "psutil>=5.9.0",
        "watchdog>=3.0.0",
        "python-daemon>=2.3.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
        "matplotlib>=3.7.0",
    ],
    entry_points={
        "console_scripts": [
            "dftool=dftool.cli:main",
            "dftoold=dftool.daemon:main",
            "dftool-eval=dftool.evaluate:main",
            "dftool-eval-plot=dftool.plot_eval:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
    ],
)
