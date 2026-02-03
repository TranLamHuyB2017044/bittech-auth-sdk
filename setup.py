from setuptools import setup, find_packages

setup(
    name="bittech-hkb-sdk",
    version="1.0.0",
    description="BitTech SDK for HKB Authentication and Connection Management",
    author="BitTech Team",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.25.0",
        "pydantic>=2.0.0",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
