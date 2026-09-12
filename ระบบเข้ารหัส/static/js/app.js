/**
 * FIDO2 / WebAuthn Client Logic
 * Handles WebAuthn registration and authentication flows.
 */

document.addEventListener('DOMContentLoaded', () => {
    checkWebAuthnSupport();
    initTabs();
    initForms();
    loadUsersList();
});

// Toast notification helper
function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'fa-info-circle';
    if (type === 'success') icon = 'fa-circle-check';
    if (type === 'error') icon = 'fa-circle-exclamation';

    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <div>${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-10px)';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// 1. WebAuthn Feature Detection
function checkWebAuthnSupport() {
    const statusBadge = document.getElementById('webauthn-status');
    const statusText = document.getElementById('status-text');

    if (window.PublicKeyCredential) {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            .then(available => {
                statusBadge.classList.add('supported');
                if (available) {
                    statusText.textContent = 'รองรับ FIDO2 / Biometrics (พร้อมใช้งาน)';
                } else {
                    statusText.textContent = 'รองรับ WebAuthn (Security Key / External)';
                }
            })
            .catch(() => {
                statusBadge.classList.add('supported');
                statusText.textContent = 'รองรับ WebAuthn';
            });
    } else {
        statusBadge.classList.add('unsupported');
        statusText.textContent = 'เบราว์เซอร์ไม่รองรับ WebAuthn';
        showToast('เบราว์เซอร์ของคุณไม่รองรับ WebAuthn API กรุณาใช้ Chrome, Edge หรือ Safari', 'error');
    }
}

// 2. Tab Navigation
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-tab');

            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetTab = document.getElementById(targetId);
            if (targetTab) targetTab.classList.add('active');

            if (targetId === 'users-tab') {
                loadUsersList();
            }
        });
    });

    const refreshBtn = document.getElementById('refresh-users-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadUsersList);
    }

    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            document.querySelector('[data-tab="login-tab"]').click();
            showToast('ออกจากระบบเรียบร้อยแล้ว', 'info');
        });
    }
}

// Helper: Convert Base64URL string to ArrayBuffer (Vanilla JS fallback)
function base64UrlToBuffer(base64Url) {
    const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const buffer = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        buffer[i] = rawData.charCodeAt(i);
    }
    return buffer.buffer;
}

// Helper: Convert ArrayBuffer to Base64URL string
function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = window.btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// 3. Forms Initialization & Handlers
function initForms() {
    const regForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');

    if (regForm) {
        regForm.addEventListener('submit', handleRegister);
    }

    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
}

// ==========================================
// FIDO2 Registration Handler
// ==========================================
async function handleRegister(e) {
    e.preventDefault();

    const username = document.getElementById('reg-username').value.trim();
    const first_name = document.getElementById('reg-firstname').value.trim();
    const last_name = document.getElementById('reg-lastname').value.trim();
    const phone_number = document.getElementById('reg-phone').value.trim();
    const btnReg = document.getElementById('btn-register');

    if (!username || !first_name || !last_name || !phone_number) {
        showToast('กรุณากรอกข้อมูลให้ครบถ้วนทุกช่อง', 'error');
        return;
    }

    try {
        btnReg.disabled = true;
        btnReg.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> กำลังเรียกใช้ WebAuthn API...';

        // Step 1: Request creation options from backend
        const beginRes = await fetch('/api/register/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, first_name, last_name, phone_number })
        });

        const beginData = await beginRes.json();
        if (!beginData.success) {
            throw new Error(beginData.message || 'ไม่สามารถสร้าง Registration Options ได้');
        }

        showToast('โปรดสแกนลายนิ้วมือ / ใบหน้า หรือกด PIN อุปกรณ์ของคุณเพื่อสร้าง Credential...', 'info', 6000);

        // Step 2: Trigger browser WebAuthn API
        let attResp;
        if (window.SimpleWebAuthnBrowser && SimpleWebAuthnBrowser.startRegistration) {
            attResp = await SimpleWebAuthnBrowser.startRegistration(beginData.options);
        } else {
            // Fallback Vanilla WebAuthn API
            const options = beginData.options;
            options.challenge = base64UrlToBuffer(options.challenge);
            options.user.id = base64UrlToBuffer(options.user.id);
            if (options.excludeCredentials) {
                options.excludeCredentials.forEach(cred => {
                    cred.id = base64UrlToBuffer(cred.id);
                });
            }

            const credential = await navigator.credentials.create({ publicKey: options });
            attResp = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                response: {
                    attestationObject: bufferToBase64Url(credential.response.attestationObject),
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                },
                type: credential.type,
                clientExtensionResults: credential.getClientExtensionResults()
            };
        }

        // Step 3: Send WebAuthn response to backend for verification
        const completeRes = await fetch('/api/register/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attResp)
        });

        const completeData = await completeRes.json();

        if (completeData.success) {
            showToast(`🎉 ${completeData.message}`, 'success', 6000);
            
            // Pre-fill login username & switch to login tab
            document.getElementById('login-username').value = username;
            setTimeout(() => {
                document.querySelector('[data-tab="login-tab"]').click();
            }, 1200);

            // Reset form
            document.getElementById('register-form').reset();
        } else {
            throw new Error(completeData.message || 'การยืนยัน Registration ล้มเหลว');
        }

    } catch (err) {
        console.error('Registration Error:', err);
        let errorMsg = err.message;
        if (err.name === 'NotAllowedError') {
            errorMsg = 'ผู้ใช้ยกเลิกการสแกนลายนิ้วมือ/ใบหน้า หรือหมดเวลา (NotAllowedError)';
        } else if (err.name === 'InvalidStateError') {
            errorMsg = 'อุปกรณ์ FIDO2 นี้ถูกลงทะเบียนไว้ในระบบแล้ว';
        }
        showToast(`เกิดข้อผิดพลาด: ${errorMsg}`, 'error', 7000);
    } finally {
        btnReg.disabled = false;
        btnReg.innerHTML = '<i class="fa-solid fa-fingerprint"></i> สมัครสมาชิกด้วย FIDO2 / WebAuthn';
    }
}

// ==========================================
// FIDO2 Authentication (Login) Handler
// ==========================================
async function handleLogin(e) {
    e.preventDefault();

    const username = document.getElementById('login-username').value.trim();
    const btnLogin = document.getElementById('btn-login');

    if (!username) {
        showToast('กรุณากรอก Username', 'error');
        return;
    }

    try {
        btnLogin.disabled = true;
        btnLogin.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> กำลังเรียกใช้ WebAuthn API...';

        // Step 1: Get authentication request options from backend
        const beginRes = await fetch('/api/authenticate/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const beginData = await beginRes.json();
        if (!beginData.success) {
            throw new Error(beginData.message || 'ไม่สามารถดึงข้อมูล Authentication Options ได้');
        }

        showToast('โปรดสแกนลายนิ้วมือ หรือใบหน้า เพื่อยืนยันตัวตน...', 'info', 6000);

        // Step 2: Trigger WebAuthn browser API
        let asseResp;
        if (window.SimpleWebAuthnBrowser && SimpleWebAuthnBrowser.startAuthentication) {
            asseResp = await SimpleWebAuthnBrowser.startAuthentication(beginData.options);
        } else {
            // Fallback Vanilla WebAuthn API
            const options = beginData.options;
            options.challenge = base64UrlToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials.forEach(cred => {
                    cred.id = base64UrlToBuffer(cred.id);
                });
            }

            const assertion = await navigator.credentials.get({ publicKey: options });
            asseResp = {
                id: assertion.id,
                rawId: bufferToBase64Url(assertion.rawId),
                response: {
                    authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
                    clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
                    signature: bufferToBase64Url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64Url(assertion.response.userHandle) : null,
                },
                type: assertion.type,
                clientExtensionResults: assertion.getClientExtensionResults()
            };
        }

        // Step 3: Complete authentication on backend
        const completeRes = await fetch('/api/authenticate/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(asseResp)
        });

        const completeData = await completeRes.json();

        if (completeData.success) {
            showToast('✅ เข้าสู่ระบบสำเร็จ!', 'success', 5000);
            displayUserProfile(completeData.user);
        } else {
            throw new Error(completeData.message || 'การยืนยันตัวตนล้มเหลว');
        }

    } catch (err) {
        console.error('Authentication Error:', err);
        let errorMsg = err.message;
        if (err.name === 'NotAllowedError') {
            errorMsg = 'ยกเลิกการสแกนนิ้วมือ/ใบหน้า หรือหมดเวลา (NotAllowedError)';
        }
        showToast(`เข้าสู่ระบบไม่สำเร็จ: ${errorMsg}`, 'error', 7000);
    } finally {
        btnLogin.disabled = false;
        btnLogin.innerHTML = '<i class="fa-solid fa-unlock-keyhole"></i> เข้าสู่ระบบด้วย FIDO2 (สแกนนิ้ว / ใบหน้า)';
    }
}

// Display profile in dashboard view upon login success
function displayUserProfile(user) {
    document.getElementById('profile-username').textContent = user.username;
    document.getElementById('profile-fullname').textContent = `${user.first_name} ${user.last_name}`;
    document.getElementById('profile-phone').textContent = user.phone_number;

    // Switch view to Dashboard Tab
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));

    const dashboardTab = document.getElementById('dashboard-tab');
    if (dashboardTab) dashboardTab.classList.add('active');
}

// 4. Load Registered Users List
async function loadUsersList() {
    const listContainer = document.getElementById('users-list');
    if (!listContainer) return;

    try {
        const res = await fetch('/api/users');
        const data = await res.json();

        if (data.success && data.users.length > 0) {
            listContainer.innerHTML = data.users.map(u => `
                <div class="user-item-card">
                    <div class="user-item-info">
                        <div class="user-avatar-mini">
                            <i class="fa-solid fa-user"></i>
                        </div>
                        <div>
                            <div class="user-name-title">${escapeHtml(u.name)} (@${escapeHtml(u.username)})</div>
                            <div class="user-meta-sub"><i class="fa-solid fa-phone"></i> ${escapeHtml(u.phone)}</div>
                        </div>
                    </div>
                    <button class="btn btn-accent btn-quick-login" onclick="quickLogin('${escapeHtml(u.username)}')">
                        <i class="fa-solid fa-key"></i> เข้าสู่ระบบ
                    </button>
                </div>
            `).join('');
        } else {
            listContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-folder-open"></i>
                    <p>ยังไม่มีผู้ใช้งานลงทะเบียนในระบบ</p>
                </div>
            `;
        }
    } catch (err) {
        console.error('Failed to load users:', err);
    }
}

// Helper quick login trigger
window.quickLogin = function(username) {
    document.getElementById('login-username').value = username;
    document.querySelector('[data-tab="login-tab"]').click();
    setTimeout(() => {
        handleLogin(new Event('submit'));
    }, 200);
};

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
