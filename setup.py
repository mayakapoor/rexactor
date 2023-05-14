import setuptools

with open("README.md", "r", encoding = "utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name = "rexactor",
    version = "1.0",
    author = "Maya Kapoor",
    author_email = "mkapoor1@uncc.edu",
    description = "An automatic regular expression signature generator",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/mayakapoor/rexactor",
    project_urls = {
        "Bug Tracker": "https://github.com/mayakapoor/rexactor/issues",
        "Documentation": "https://rexactor.readthedocs.io/en/latest/"
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "rexactor = rexactor:main"
        ]
    },
    install_requires=[
          'tapcap',
      ],
    python_requires = ">=3.6"
)
