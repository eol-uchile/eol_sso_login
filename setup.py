import os
from setuptools import setup

def package_data(pkg, roots):
    """Generic function to find package_data.
    All of the files under each of the `roots` will be declared as package
    data for package `pkg`.
    """
    data = []
    for root in roots:
        for dirname, _, files in os.walk(os.path.join(pkg, root)):
            for fname in files:
                data.append(os.path.relpath(os.path.join(dirname, fname), pkg))

    return {pkg: data}

setup(
    name="eol_sso_login",
    version="0.0.4",
    author="Oficina EOL UChile",
    author_email="eol-ing@uchile.cl",
    description="Authentication backend for EOL from UChile api and Enroll/Unenroll/Export users",
    long_description="Authentication backend for EOL from UChile api and Enroll/Unenroll/Export users",
    url="https://github.com/eol-uchile/eol_sso_login",
    packages=['eol_sso_login'],
    package_data=package_data("eol_sso_login", ["static", "locale"]),
    install_requires=["unidecode>=1.1.1"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "lms.djangoapp": ["eol_sso_login = eol_sso_login.apps:EolSSOLoginConfig"],
        "cms.djangoapp": ["eol_sso_login = eol_sso_login.apps:EolSSOLoginConfig"]
    },
)
