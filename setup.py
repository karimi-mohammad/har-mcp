from setuptools import setup, find_packages

setup(
    name="har-mcp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["fastmcp>=4.0"],
    entry_points={
        "console_scripts": [
            "har-mcp=har_mcp.server:main",
        ],
    },
)
