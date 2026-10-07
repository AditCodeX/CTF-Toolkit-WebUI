// CTF Toolkit - Core Runtime & UI Helpers

// Toast Notification System
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.25s ease';
        setTimeout(() => toast.remove(), 250);
    }, 2500);
}

// Utility function to copy text to clipboard with fallback
async function copyToClipboard(text, buttonElement) {
    if (!text && text !== '') {
        showToast('Nothing to copy', 'error');
        return false;
    }

    let success = false;
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            success = true;
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-999999px';
            textarea.style.top = '-999999px';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            success = document.execCommand('copy');
            textarea.remove();
        }
    } catch (err) {
        console.error('Failed to copy text: ', err);
    }

    if (success) {
        showToast('Copied to clipboard!', 'success');
        if (buttonElement) {
            const feedback = buttonElement.querySelector('.copy-feedback') || createCopyFeedback(buttonElement);
            feedback.classList.add('show');
            setTimeout(() => {
                feedback.classList.remove('show');
            }, 1800);
        }
        return true;
    } else {
        showToast('Failed to copy to clipboard', 'error');
        return false;
    }
}

// Create copy feedback element
function createCopyFeedback(buttonElement) {
    const feedback = document.createElement('span');
    feedback.className = 'copy-feedback';
    feedback.textContent = 'Copied!';
    buttonElement.appendChild(feedback);
    return feedback;
}

// Clear input and output fields
function clearFields(...fieldIds) {
    fieldIds.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' || element.tagName === 'SELECT') {
                element.value = '';
            } else {
                element.textContent = '';
                element.innerHTML = '';
            }
        }
    });
}

// Show/hide output section
function toggleOutput(outputId, show = true) {
    const outputSection = document.getElementById(outputId);
    if (outputSection) {
        if (show) {
            outputSection.classList.remove('hidden');
        } else {
            outputSection.classList.add('hidden');
        }
    }
}

// Format output with proper styling
function formatOutput(outputElement, content, isError = false) {
    if (outputElement) {
        outputElement.textContent = content;
        outputElement.className = isError ? 'output-content error' : 'output-content';
    }
}

// Global active navigation handler
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname.toLowerCase();
    const navItems = document.querySelectorAll('.nav-item');

    let currentFile = 'index.html';
    if (path.includes('crypto.html')) {
        currentFile = 'crypto.html';
    } else if (path.includes('encoding.html')) {
        currentFile = 'encoding.html';
    } else if (path.includes('web.html')) {
        currentFile = 'web.html';
    } else if (path.includes('misc.html')) {
        currentFile = 'misc.html';
    }

    navItems.forEach(item => {
        const href = (item.getAttribute('href') || '').toLowerCase();
        if (href.endsWith(currentFile) || (currentFile === 'index.html' && (href === 'index.html' || href === '../index.html'))) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Delegated copy button listener
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.copy-btn');
        if (btn) {
            const targetId = btn.getAttribute('data-target');
            const targetPayload = btn.getAttribute('data-payload');

            if (targetPayload) {
                copyToClipboard(targetPayload, btn);
            } else if (targetId) {
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    const textToCopy = targetElement.tagName === 'INPUT' || targetElement.tagName === 'TEXTAREA'
                        ? targetElement.value
                        : targetElement.textContent;
                    copyToClipboard(textToCopy, btn);
                }
            }
        }
    });
});

// Export utility functions for use in other modules
window.ctfToolkit = {
    copyToClipboard,
    clearFields,
    toggleOutput,
    formatOutput,
    showToast
};
