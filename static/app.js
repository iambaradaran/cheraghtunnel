document.addEventListener('DOMContentLoaded', () => {
    // Session Auth State check
    const token = localStorage.getItem('cheragh_session');
    if (token) {
        showDashboard();
    }

    // Login Form Submit
    const loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = loginForm.username.value;
        const password = loginForm.password.value;
        
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            console.log('Login response:', data);
            if (data.success) {
                localStorage.setItem('cheragh_session', data.token);
                showDashboard();
            } else {
                showLoginError(data.message);
            }
        } catch (err) {
            showLoginError("Error connecting to server");
        }
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', () => {
        localStorage.removeItem('cheragh_session');
        window.location.reload();
    });

    // Create Modal Opens/Closes
    const openCreateBtn = document.getElementById('open-create-modal');
    const closeCreateBtn = document.getElementById('close-create-modal');
    const createModal = document.getElementById('create-modal');
    
    openCreateBtn.addEventListener('click', () => {
        // Preset random token
        document.getElementById('tunnel-token').value = Math.random().toString(36).substring(2, 12).toUpperCase();
        createModal.style.display = 'flex';
    });
    
    closeCreateBtn.addEventListener('click', () => {
        createModal.style.display = 'none';
    });

    // Generate token button
    document.getElementById('gen-token-btn').addEventListener('click', () => {
        document.getElementById('tunnel-token').value = Math.random().toString(36).substring(2, 12).toUpperCase();
    });

    // Show/Hide decoy input based on protocol
    const protoSelect = document.getElementById('tunnel-protocol');
    protoSelect.addEventListener('change', () => {
        const val = protoSelect.value;
        const decoyGroup = document.getElementById('decoy-group');
        if (val === 'mirage' || val === 'aura' || val === 'nova') {
            decoyGroup.style.display = 'block';
        } else {
            decoyGroup.style.display = 'none';
        }
    });

    // Create Form Submit
    const createForm = document.getElementById('create-tunnel-form');
    createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById('tunnel-name').value,
            protocol: document.getElementById('tunnel-protocol').value,
            iran_port: parseInt(document.getElementById('iran-port').value),
            control_port: parseInt(document.getElementById('control-port').value),
            kharej_port: parseInt(document.getElementById('kharej-port').value),
            token: document.getElementById('tunnel-token').value,
            decoy_url: document.getElementById('decoy-url').value || null,
            backup_ips: document.getElementById('backup-ips').value || null,
            status: "inactive",
            stats_rx: 0,
            stats_tx: 0,
            stats_speed_rx: 0,
            stats_speed_tx: 0
        };

        try {
            const res = await apiFetch('/api/tunnels', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                createModal.style.display = 'none';
                createForm.reset();
                loadTunnels();
            } else if (res) {
                alert("Failed to create tunnel config");
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Close command modal
    document.getElementById('close-cmd-modal').addEventListener('click', () => {
        document.getElementById('cmd-modal').style.display = 'none';
    });

    // Close deploy modal
    document.getElementById('close-deploy-modal').addEventListener('click', () => {
        document.getElementById('deploy-modal').style.display = 'none';
    });

    // SSH Deploy Form Submit
    const deployForm = document.getElementById('deploy-tunnel-form');
    deployForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('deploy-tunnel-id').value;
        const payload = {
            host: document.getElementById('ssh-host').value,
            port: parseInt(document.getElementById('ssh-port').value),
            username: document.getElementById('ssh-user').value,
            password: document.getElementById('ssh-password').value || null,
            panel_host: window.location.host
        };

        // Hide modal and show notification
        document.getElementById('deploy-modal').style.display = 'none';
        alert("SSH Auto-Deployment task initiated in background. Check tunnel status shortly!");

        try {
            const res = await apiFetch(`/api/tunnels/${id}/deploy`, {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                loadTunnels();
            }
        } catch (err) {
            console.error(err);
        }
    });
});

function showDashboard() {
    document.getElementById('login-container').style.display = 'none';
    document.getElementById('dashboard-container').style.display = 'block';
    
    // Auto-fill host IP in diagram
    document.getElementById('iran-ip-label').innerText = window.location.hostname;

    // Load initial data
    loadTunnels();
    loadStats();

    // Start polling stats and tunnels
    setInterval(loadStats, 3000);
    setInterval(loadTunnels, 2000); // Poll tunnels more frequently to reflect live speeds
}

function showLoginError(msg) {
    const errorEl = document.getElementById('login-error');
    errorEl.innerText = msg;
    errorEl.style.display = 'block';
}

function formatSpeed(bytesPerSec) {
    if (!bytesPerSec || bytesPerSec === 0) return "0 KB/s";
    const kb = bytesPerSec / 1024;
    if (kb < 1024) {
        return `${kb.toFixed(1)} KB/s`;
    }
    const mb = kb / 1024;
    return `${mb.toFixed(1)} MB/s`;
}

async function loadTunnels() {
    try {
        const res = await apiFetch('/api/tunnels');
        if (!res || !res.ok) return;
        const tunnels = await res.json();
        
        const body = document.getElementById('tunnels-body');
        body.innerHTML = '';
        
        let activeCount = 0;
        tunnels.forEach(t => {
            if (t.status === 'active') activeCount++;
            
            const tr = document.createElement('tr');
            
            // Format status badge
            const statusClass = t.status === 'active' ? 'active' : (t.status === 'deploying' ? 'deploying' : (t.status === 'error' ? 'error' : 'inactive'));
            const statusText = t.status.toUpperCase();
            
            tr.innerHTML = `
                <td><strong>${t.name}</strong></td>
                <td><span class="proto-name">${t.protocol.toUpperCase()}</span></td>
                <td>${t.iran_port}</td>
                <td>${t.control_port}</td>
                <td>${t.kharej_port}</td>
                <td>
                    <div class="status-pill ${statusClass}">
                        <div class="dot"></div>
                        ${statusText}
                    </div>
                </td>
                <td>
                    <span style="color: var(--color-cyan); font-weight: 500;">↓ ${formatSpeed(t.stats_speed_rx)}</span> / 
                    <span style="color: var(--color-orange); font-weight: 500;">↑ ${formatSpeed(t.stats_speed_tx)}</span>
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="toggleTunnel(${t.id})">
                            ${t.status === 'active' ? 'Stop' : 'Start'}
                        </button>
                        <button class="btn btn-secondary" onclick="showDeployModal(${t.id})">SSH Deploy</button>
                        <button class="btn btn-secondary" onclick="showNodeCommand(${t.id})">Node Cmd</button>
                        <button class="btn btn-secondary btn-danger" style="background: rgba(255,51,102,0.15); color: #ff3366;" onclick="deleteTunnel(${t.id})">Delete</button>
                    </div>
                </td>
            `;
            body.appendChild(tr);
        });

        document.getElementById('active-count').innerText = `${activeCount} / ${tunnels.length}`;
    } catch (err) {
        console.error(err);
    }
}

async function loadStats() {
    try {
        const res = await apiFetch('/api/stats');
        if (!res || !res.ok) return;
        const stats = await res.json();
        
        // Update CPU Circular Ring
        const cpuCircle = document.getElementById('cpu-circle');
        const cpuText = document.getElementById('cpu-text');
        const cpuVal = Math.round(stats.cpu_usage);
        cpuCircle.setAttribute('stroke-dasharray', `${cpuVal}, 100`);
        cpuText.innerText = `${cpuVal}%`;

        // Update RAM Circular Ring
        const ramCircle = document.getElementById('ram-circle');
        const ramText = document.getElementById('ram-text');
        const ramVal = Math.round(stats.mem_usage);
        ramCircle.setAttribute('stroke-dasharray', `${ramVal}, 100`);
        ramText.innerText = `${ramVal}%`;

    } catch (err) {
        console.error(err);
    }
}

async function toggleTunnel(id) {
    try {
        const res = await apiFetch(`/api/tunnels/${id}/toggle`, { method: 'POST' });
        if (res && res.ok) {
            loadTunnels();
        }
    } catch (err) {
        console.error(err);
    }
}

async function deleteTunnel(id) {
    if (!confirm("Are you sure you want to delete this tunnel configuration?")) return;
    try {
        const res = await apiFetch(`/api/tunnels/${id}`, { method: 'DELETE' });
        if (res && res.ok) {
            loadTunnels();
        }
    } catch (err) {
        console.error(err);
    }
}

function showNodeCommand(id) {
    const host = window.location.host;
    const cmd = `curl -sSf http://${host}/api/tunnels/${id}/node-script | bash`;
    
    document.getElementById('node-command-text').innerText = cmd;
    
    const copyBtn = document.getElementById('copy-cmd-btn');
    copyBtn.innerText = 'Copy Command';
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(cmd);
        copyBtn.innerText = 'Copied!';
    };
    
    document.getElementById('cmd-modal').style.display = 'flex';
}

function showDeployModal(id) {
    document.getElementById('deploy-tunnel-id').value = id;
    document.getElementById('deploy-modal').style.display = 'flex';
}

// Helper to get auth headers for API calls
function authHeaders() {
    const token = localStorage.getItem('cheragh_session');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

// Wrapper for API calls to handle 401 logouts gracefully
async function apiFetch(url, options = {}) {
    const headers = authHeaders();
    options.headers = { ...headers, ...options.headers };
    try {
        const res = await fetch(url, options);
        if (res.status === 401) {
            localStorage.removeItem('cheragh_session');
            window.location.reload();
            return null;
        }
        return res;
    } catch (err) {
        console.error("API Fetch Error:", err);
        return null;
    }
}

window.toggleTunnel = toggleTunnel;
window.deleteTunnel = deleteTunnel;
window.showNodeCommand = showNodeCommand;
window.showDeployModal = showDeployModal;
