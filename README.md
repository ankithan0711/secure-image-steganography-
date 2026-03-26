# 🔐 Secure Image Communication using Steganography

This project is a secure file sharing system that hides encrypted files inside images using steganography.

## Features
- AES encryption for security
- LSB steganography to hide data in images
- Token-based secure access
- Flask web application

## Technologies Used
- Python
- Flask
- OpenCV
- Cryptography

## How it works
1. Upload a PNG image and secret file
2. File is encrypted and hidden inside image
3. A token and link are generated
4. User can retrieve file using token

## Run Project
pip install -r requirements.txt  
python app.py
