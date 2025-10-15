# StegoSec: ChaCha20 Steganography Web Tool

StegoSec is a web-based steganography application that allows you to hide a secret message within an image file and retrieve it later. The project uses a powerful combination of **Least Significant Bit (LSB)** steganography for embedding the data and the modern **ChaCha20 stream cipher** for encrypting the message, ensuring both secrecy and security.

The application features a sleek, mobile-responsive web interface with a dark, neon theme, and is powered by a Python Flask backend that handles all the heavy cryptographic and image processing tasks.

## Features

* **Encrypt Mode**: Hide any text message inside a cover image (`.png` or `.jpg`).
* **Decrypt Mode**: Reveal a hidden message from an encrypted image.
* **Strong Security**: Messages are encrypted using a from-scratch implementation of the **ChaCha20** algorithm before being embedded.
* **LSB Steganography**: Uses the Least Significant Bit technique to hide data with minimal visual changes to the image.
* **Web Interface**: A modern, intuitive, and mobile-responsive UI built with HTML, CSS, and JavaScript.
* **Client-Server Architecture**: A robust backend powered by Python and Flask handles all processing, ensuring the web interface is always fast and responsive.

## Technology Stack

* **Backend**: Python, Flask, Flask-Cors, OpenCV, NumPy
* **Frontend**: HTML, CSS, JavaScript
* **Cryptography**: ChaCha20 (implemented from scratch in Python)
* **Steganography Method**: Least Significant Bit (LSB)

## Project Structure

The project follows a standard Flask web application structure:
```bash
steganography_project/
├── app.py              # Main Python Flask server
│
├── templates/
│   └── index.html      # Frontend HTML structure
│
└── static/
    ├── style.css       # CSS for styling
    └── script.js       # JavaScript for frontend logic
```

## Setup and Usage

To run this project, you will need Python 3 installed on your system.

### 1. Create the Project Structure

Create the folders (`templates`, `static`) and files as shown in the structure diagram above. Place the corresponding code into each file.

### 2. Install Dependencies

Navigate to the project's main directory in your terminal or command prompt and install the required Python libraries using pip:

```bash
pip install Flask Flask-Cors opencv-python numpy
```
3. Run the Backend Server
Once the libraries are installed, start the Flask web server by running the following command in the same terminal:
```bash
python app.py
```
You should see output indicating that the server is running, typically on http://127.0.0.1:5000. Keep this terminal window open.

4. Open the Web Application
Open your web browser (like Chrome, Firefox, etc.) and go to the following address:

https://www.google.com/url?sa=E&source=gmail&q=http://127.0.0.1:5000

The StegoSec web interface will load, and you can now start encrypting and decrypting images.