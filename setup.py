from setuptools import setup

description = """Web based CA Manager"""

setup(
    name='Mina.CA',
    version='1.0',
    long_description=description,
    packages=['ca'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask>1.1',
        'flask-login',
        'sqlalchemy==1.4',
        'pexpect',
        'psycopg2-binary',
        'wtforms',
        'python-slugify',
        'paginate',
        'paginate-sqlalchemy',
        'sqlalchemy-stubs',
        'pyopenssl'],
    extra_features=[
        'unicode'
    ]
)
