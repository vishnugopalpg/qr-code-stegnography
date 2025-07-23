from setuptools import setup, find_packages

setup(
    name='qr-stego-secure',
    version='1.0.6',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=42.0.0',
        'Pillow>=10.0.0',
        'qrcode[pil]>=7.4.2',
    ],
    entry_points={
        'console_scripts': [
            'qr-stego=qr_stego.__main__:main',
        ],
    },
    author='Vishnu',
    description='Secure QR Steganography and Encryption Tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
    ],
    python_requires='>=3.7',
)
