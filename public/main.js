
const form = document.getElementById('secretForm');
const resultDiv = document.getElementById('result');
const errorDiv = document.getElementById('error');
const submitBtn = document.getElementById('submitBtn');

let maxSecretLength = 50000; // Default fallback

// Security: Input sanitization functions
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    // Remove HTML tags and dangerous characters
    return input
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .replace(/data:/gi, '') // Remove data: URLs
        .replace(/vbscript:/gi, '') // Remove VBScript
        .trim();
}

function sanitizeNumericInput(input) {
    const num = parseInt(input);
    return isNaN(num) ? 0 : Math.max(0, Math.min(num, 999999));
}

function sanitizeSeparator(input) {
    if (typeof input !== 'string') return '-';
    
    // Only allow safe separator characters
    const safeSeparators = /^[._\-#@$%&*+=|~`^!?]+$/;
    const cleaned = input.slice(0, 10); // Max 10 chars
    
    return safeSeparators.test(cleaned) ? cleaned : '-';
}

// Fetch config from server
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (response.ok) {
            const config = await response.json();
            maxSecretLength = config.maxSecretLength;
        }
    } catch (error) {
        console.warn('Could not load config, using defaults');
    }
}

function showError(message) {
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    resultDiv.style.display = 'none';
}

function hideError() {
    errorDiv.style.display = 'none';
}



async function copyLink(event) {
    const link = document.getElementById('secretLink').textContent;
    try {
        await navigator.clipboard.writeText(link);
        const btn = document.getElementById('copyLinkBtn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    } catch (err) {
        console.error('Failed to copy link:', err);
    }
}

secretForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    hideError();
    
    const secretText = document.getElementById('secretText').value;
    const expiration = document.getElementById('expiration').value;
    const submitBtn = document.getElementById('submitBtn');
    
    submitBtn.innerHTML = 'Encrypting... <span class="loading"></span>';
    submitBtn.disabled = true;
    
    try {
        const { encryptedData, iv } = await encryptText(secretText);
        
        const response = await fetch('/api/store', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ encryptedData, iv, expiration })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to store secret');
        }
        
        const data = await response.json();
        
        const secretLink = `${window.location.origin}/view/${data.id}#key=${getSecretKey()}`;
        
        document.getElementById('secretLink').textContent = secretLink;
        document.getElementById('expirationInfo').textContent = `This link will expire in ${expiration / 60} hours.`;
        
        secretForm.style.display = 'none';
        result.style.display = 'block';
        
    } catch (error) {
        console.error('Error:', error);
        showError(error.message || 'An unexpected error occurred.');
    } finally {
        submitBtn.innerHTML = 'Encrypt & Create Link';
        submitBtn.disabled = false;
    }
});

// Add event listener for copy button
document.getElementById('copyLinkBtn').addEventListener('click', copyLink);

// Add event listener for double-click on link text
document.getElementById('secretLink').addEventListener('dblclick', copyLink);

// Add event listener for new link button
document.getElementById('newLinkBtn').addEventListener('click', function(e) {
    e.preventDefault();
    
    hideError();
    
    // Show all hidden elements again
    document.querySelector('.header').style.display = 'block';
    form.style.display = 'block';
    
    // Hide the result container
    document.getElementById('result').style.display = 'none';
    
    // Clear the form and reset to default values
    form.reset();
    document.getElementById('secretText').value = '';
    document.getElementById('expiration').value = '480';
    
    // Reset tab selection to default (8 hours)
    document.querySelectorAll('.expiration-tab').forEach(t => t.classList.remove('active'));
    document.querySelector('.expiration-tab[data-minutes="480"]').classList.add('active');
    
    // Clear the URL hash
    window.location.hash = '';
});

// Password visibility toggle functionality
function togglePasswordVisibility() {
    const textarea = document.getElementById('secretText');
    const toggle = document.getElementById('visibilityToggle');
    
    if (toggle.checked) {
        textarea.style.webkitTextSecurity = 'none';
        textarea.style.textSecurity = 'none';
    } else {
        textarea.style.webkitTextSecurity = 'disc';
        textarea.style.textSecurity = 'disc';
    }
}


// Initialize password field as visible (since toggle is checked by default)
document.addEventListener('DOMContentLoaded', async () => {
    const textarea = document.getElementById('secretText');
    textarea.style.webkitTextSecurity = 'none';
    textarea.style.textSecurity = 'none';
    
    // Force generator toggle to start OFF on every page load
    const generatorToggle = document.getElementById('generatorToggle');
    generatorToggle.checked = false;
    toggleGeneratorSection(); // Apply the initial state
    
    // Load configuration from server
    await loadConfig();
});

// Tab-style expiration selector functionality
document.querySelectorAll('.expiration-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active class from all tabs
        document.querySelectorAll('.expiration-tab').forEach(t => t.classList.remove('active'));
        // Add active class to clicked tab
        tab.classList.add('active');
        // Update hidden input value
        document.getElementById('expiration').value = tab.getAttribute('data-minutes');
    });
});

// Add event listener for password toggle switch
document.getElementById('visibilityToggle').addEventListener('change', togglePasswordVisibility);

// Generator section toggle functionality
function toggleGeneratorSection() {
    const generatorSection = document.getElementById('generatorSection');
    const toggle = document.getElementById('generatorToggle');
    
    if (toggle.checked) {
        generatorSection.style.display = 'block';
    } else {
        generatorSection.style.display = 'none';
        // Clear any generated password when hiding the section
        currentGeneratedPassword = '';
    }
}

// Add event listener for generator section toggle
document.getElementById('generatorToggle').addEventListener('change', toggleGeneratorSection);


// Password generator functionality
let currentGeneratedPassword = '';

// Tab switching
document.querySelectorAll('.generator-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.generator-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        const type = tab.getAttribute('data-type');
        document.getElementById('passwordOptions').style.display = type === 'password' ? 'block' : 'none';
        document.getElementById('passphraseOptions').style.display = type === 'passphrase' ? 'block' : 'none';
        
        // Clear any generated password when switching tabs
        currentGeneratedPassword = '';
    });
});

// Generate password
document.getElementById('generateBtn').addEventListener('click', async () => {
    hideError();
    
    const activeTab = document.querySelector('.generator-tab.active');
    const type = activeTab.getAttribute('data-type');
    
    let requestData = { type };
    
    // Security: Sanitize all generator inputs
    if (type === 'password') {
        const lengthInput = document.getElementById('passwordLength').value;
        requestData.length = sanitizeNumericInput(lengthInput);
        
        // Validate password length range
        if (requestData.length < 4 || requestData.length > 128) {
            showError('Password length must be between 4 and 128 characters');
            return;
        }
    } else {
        const wordCountInput = document.getElementById('wordCount').value;
        const separatorInput = document.getElementById('separator').value;
        
        requestData.wordCount = sanitizeNumericInput(wordCountInput);
        requestData.separator = sanitizeSeparator(separatorInput);
        
        // Validate word count range
        if (requestData.wordCount < 2 || requestData.wordCount > 10) {
            showError('Word count must be between 2 and 10 words');
            return;
        }
    }
    
    try {
        const response = await fetch('/api/generate-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate password');
        }
        
        const data = await response.json();
        currentGeneratedPassword = data.password;
        
        // Directly populate the main textarea with the generated password
        document.getElementById('secretText').value = currentGeneratedPassword;
        
        // Focus on the textarea
        document.getElementById('secretText').focus();
        
    } catch (error) {
        console.error('Error generating password:', error);
        showError(error.message || 'Failed to generate password. Please try again.');
    }
});
