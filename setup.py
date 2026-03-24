"""
LySec - Linux Forensics Monitoring Daemon
Setup script for installation.
"""

from setuptools import setup, find_packages

setup(
    name="lysec",
    version="1.0.0",
    description="LySec Linux Forensics Monitoring - Detect, Log, Alert (No Prevention)",
    author="LySec Team",
    license="MIT",
    packages=find_packages(where="src", include=["lysec", "lysec.*"]),
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
    extras_require={
        "fuzzy": [
            "ssdeep>=3.4",
            "py-tlsh>=4.7.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "lysec=lysec.cli:main",
            "lysecd=lysec.daemon:main",
            "lysec-eval=lysec.evaluate:main",
            "lysec-eval-plot=lysec.plot_eval:main",
            "lysec-gui=lysec.gui:main",
            "lysec-watchdog=lysec.watchdog:main",
            "dftool=lysec.cli:main",
            "dftoold=lysec.daemon:main",
            "dftool-eval=lysec.evaluate:main",
            "dftool-eval-plot=lysec.plot_eval:main",
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
