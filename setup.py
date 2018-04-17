from setuptools import setup

setup(
    name='jupyterhub-winauthenticator',
    version='1.0',
    description='Windows Authenticator for JupyterHub',
    url='https://github.com/ni/jupyterhub-winapauthenticator',
    author='Alejandro del Castillo',
    license='MIT',
    packages=['winauthenticator'],
    install_requires=[
        'pywin32',
        'jupyterhub',
    ]
)
