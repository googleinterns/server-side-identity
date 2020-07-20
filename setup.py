# Copyright 2016 Google LLC
# Modifications: Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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