const revealBtn = document.getElementById('revealBtn');
const secretContent = document.getElementById('secretContent');
const secretText = document.getElementById('secretText');
const errorDiv = document.getElementById('error');

function showError(message) {
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    secretContent.style.display = 'none';
}

function setLoading(loading) {
    if (loading) {
        revealBtn.innerHTML = 'Decrypting... <span class="loading"></span>';
        revealBtn.disabled = true;
    } else {
        revealBtn.innerHTML = 'Reveal Secret';
        revealBtn.disabled = false;
    }
}

async function copySecret(event) {
    const text = secretText.value;
    try {
        await navigator.clipboard.writeText(text);
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = '#20c997';
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '#3b82f6';
        }, 2000);
    } catch (err) {
        console.error('Failed to copy secret:', err);
    }
}

function autoResizeTextarea(textarea) {
    textarea.style.height = '72px'; // Reset to 3 lines height
    const scrollHeight = textarea.scrollHeight;
    textarea.style.height = Math.min(scrollHeight, 500) + 'px';
}

revealBtn.addEventListener('click', async () => {
    const pathParts = window.location.pathname.split('/');
    const secretId = pathParts[pathParts.length - 1];
    
    if (!secretId) {
        showError('Invalid secret link');
        return;
    }
    
    setLoading(true);
    
    try {
        const response = await fetch(`/api/retrieve/${secretId}`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to retrieve secret');
        }
        
        const data = await response.json();
        
        const decryptedText = await decryptText(data.encryptedData, data.iv);
        
        secretText.value = decryptedText;
        autoResizeTextarea(secretText);
        secretContent.style.display = 'block';
        revealBtn.style.display = 'none';
        
    } catch (error) {
        console.error('Error retrieving secret:', error);
        showError(error.message || 'Failed to retrieve secret. The link may have expired or already been used.');
    } finally {
        setLoading(false);
    }
});

// Add event listener for copy button
document.getElementById('copySecretBtn').addEventListener('click', copySecret);

window.addEventListener('beforeunload', () => {
    if (secretText.value) {
        secretText.value = '';
    }
});
