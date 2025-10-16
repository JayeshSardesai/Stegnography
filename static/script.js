// --- Tab switching logic ---
function openTab(evt, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) { tabcontent[i].style.display = "none"; }
    tablinks = document.getElementsByClassName("tab-link");
    for (i = 0; i < tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(" active", ""); }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelector('.tab-link').click();

    // --- Password visibility toggle ---
    document.querySelectorAll('.toggle-password').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const passwordInput = toggle.previousElementSibling;
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggle.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                toggle.textContent = '👁️';
            }
        });
    });
});

const statusMessage = document.getElementById('status-message');

function setStatus(message, isError = false) {
    statusMessage.textContent = message;
    statusMessage.style.color = isError ? 'var(--secondary-neon)' : 'var(--primary-neon)';
}

function handleImageUpload(event, canvasId) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
        const img = new Image();
        img.onload = function () {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);
        }
        img.src = e.target.result;
    }
    reader.readAsDataURL(file);
}

// --- Event Listeners for Uploads ---
document.getElementById('encrypt-upload').addEventListener('change', (e) => handleImageUpload(e, 'encrypt-canvas-preview'));
document.getElementById('decrypt-upload').addEventListener('change', (e) => handleImageUpload(e, 'decrypt-canvas-preview'));

// --- ENCRYPTION: Send data to Python server ---
document.getElementById('encrypt-button').addEventListener('click', async () => {
    const imageInput = document.getElementById('encrypt-upload');
    const message = document.getElementById('secret-message').value;
    const key = document.getElementById('encrypt-key').value;
    const downloadButton = document.getElementById('download-link');

    // Reset download button state
    downloadButton.classList.add('disabled');
    downloadButton.href = '#';

    if (!imageInput.files[0]) { setStatus('Error: Please select an image.', true); return; }
    if (!message) { setStatus('Error: Please enter a message.', true); return; }
    if (!key) { setStatus('Error: Please enter a key.', true); return; }

    setStatus('Uploading and encrypting... Please wait.');

    const formData = new FormData();
    formData.append('image', imageInput.files[0]);
    formData.append('message', message);
    formData.append('key', key);

    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            body: formData,
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);

            // Display the result image in the result canvas
            const resultCanvas = document.getElementById('encrypted-canvas-result');
            const resultCtx = resultCanvas.getContext('2d');
            const img = new Image();
            img.onload = () => {
                resultCanvas.width = img.width;
                resultCanvas.height = img.height;
                resultCtx.drawImage(img, 0, 0);
            };
            img.src = url;

            // UPDATED: Prepare the download button instead of auto-downloading
            downloadButton.href = url;
            downloadButton.download = 'encrypted.png'; // Set the default filename
            downloadButton.classList.remove('disabled'); // Enable the button

            setStatus('Encryption successful! Click the button to download.');
        } else {
            const error = await response.json();
            setStatus(`Error: ${error.error}`, true);
        }
    } catch (error) {
        setStatus('Error: Could not connect to the server. Is it running?', true);
    }
});

// --- DECRYPTION: Send data to Python server ---
document.getElementById('decrypt-button').addEventListener('click', async () => {
    const imageInput = document.getElementById('decrypt-upload');
    const key = document.getElementById('decrypt-key').value;

    if (!imageInput.files[0]) { setStatus('Error: Please select an image.', true); return; }
    if (!key) { setStatus('Error: Please enter the key.', true); return; }

    setStatus('Uploading and decrypting... Please wait.');

    const formData = new FormData();
    formData.append('image', imageInput.files[0]);
    formData.append('key', key);

    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            body: formData,
        });

        if (response.ok) {
            const data = await response.json();
            document.getElementById('revealed-message').value = data.message;
            setStatus('Decryption successful!');
        } else {
            const error = await response.json();
            setStatus(`Error: ${error.error || 'Decryption failed.'}`, true);
        }
    } catch (error) {
        setStatus('Error: Could not connect to the server. Is it running?', true);
    }
});