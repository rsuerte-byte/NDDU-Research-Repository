const AUTH_STORAGE_KEY = 'nddu-repo-auth';
const AUTH_EMAIL_KEY = 'nddu-repo-email';

function isInstitutionalEmail(email) {
    return /^[^@\s]+@nddu\.edu\.ph$/i.test(email.trim());
}

function getStoredAuth() {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!stored) return null;

    try {
        return JSON.parse(stored);
    } catch (error) {
        return null;
    }
}

function setStoredAuth(email) {
    const normalizedEmail = email.trim().toLowerCase();
    localStorage.setItem(
        AUTH_STORAGE_KEY,
        JSON.stringify({ authenticated: true, email: normalizedEmail, loggedAt: Date.now() })
    );
    localStorage.setItem(AUTH_EMAIL_KEY, normalizedEmail);
}

function clearStoredAuth() {
    localStorage.removeItem(AUTH_STORAGE_KEY);
    localStorage.removeItem(AUTH_EMAIL_KEY);
}

async function requireRepositoryAccess(redirectPath = 'login.html') {
    try {
        const response = await fetch('/api/me');
        const data = await response.json();

        if (!response.ok || !data?.success) {
            window.location.href = redirectPath;
            return false;
        }

        setStoredAuth(data.user.email);
        return true;
    } catch (error) {
        window.location.href = redirectPath;
        return false;
    }
}

function updateAuthUI() {
    const auth = getStoredAuth();
    const statusEl = document.getElementById('authStatus');
    const emailEl = document.getElementById('userEmail');
    const logoutBtn = document.getElementById('logoutBtn');

    if (!auth?.authenticated) return;

    if (statusEl) statusEl.classList.remove('hidden');
    if (emailEl) emailEl.textContent = auth.email;
    if (logoutBtn) logoutBtn.classList.remove('hidden');
}

async function logoutUser() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout failed', error);
    }

    clearStoredAuth();
    window.location.href = 'index.html';
}
