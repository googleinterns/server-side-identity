import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gsi-verification", # Replace with your own username
    version="0.0.1",
    author="Google LLC",
    author_email="sotremba@google.com",
    description="Server side library for id_token verification and decoding",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/googleinterns/server-side-identity",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*",
    license="Apache 2.0",
)