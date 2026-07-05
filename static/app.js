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

    // Show/Hide dynamic options based on protocol
    const DECOY_PROTOCOLS = ['aura', 'nova', 'glimmer', 'beacon', 'mirage'];
    
    function toggleDecoyVisibility(protocol, groupId) {
        const group = document.getElementById(groupId);
        if (group) {
            if (DECOY_PROTOCOLS.includes(protocol)) {
                group.style.display = 'block';
            } else {
                group.style.display = 'none';
            }
        }
    }
    window.toggleDecoyVisibility = toggleDecoyVisibility; // Expose globally for showEditModal

    const protoSelect = document.getElementById('tunnel-protocol');
    protoSelect.addEventListener('change', () => {
        renderDynamicOptions(protoSelect.value, 'dynamic-options-container');
        toggleDecoyVisibility(protoSelect.value, 'decoy-group');
    });
    // Trigger initial render
    renderDynamicOptions(protoSelect.value, 'dynamic-options-container');
    toggleDecoyVisibility(protoSelect.value, 'decoy-group');

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
            decoy_url: DECOY_PROTOCOLS.includes(document.getElementById('tunnel-protocol').value)
                ? document.getElementById('decoy-url').value || "google.com"
                : null,
            transport_options: extractDynamicOptions('dynamic-options-container'),
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
                const errMsg = await res.text();
                alert(errMsg || "Failed to create tunnel config");
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

    // Node Deploy Custom Fields Toggle
    document.getElementById('deploy-kharej-select');
    const deployIranSelect = document.getElementById('deploy-iran-select');
    
    document.getElementById('open-add-node-modal').addEventListener('click', () => {
        document.getElementById('add-node-modal').style.display = 'flex';
    });
    document.getElementById('close-add-node-modal').addEventListener('click', () => {
        document.getElementById('add-node-modal').style.display = 'none';
    });
    
    document.getElementById('add-node-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById('add-node-name').value,
            role: document.getElementById('add-node-role').value,
            host: document.getElementById('add-node-host').value,
            port: parseInt(document.getElementById('add-node-port').value),
            username: document.getElementById('add-node-user').value,
            password: document.getElementById('add-node-pass').value || null,
            private_key: document.getElementById('add-node-key').value || null
        };
        try {
            const res = await apiFetch('/api/nodes', { method: 'POST', body: JSON.stringify(payload) });
            if (res && res.ok) {
                document.getElementById('add-node-modal').style.display = 'none';
                document.getElementById('add-node-form').reset();
                loadNodes();
            } else {
                alert("Failed to add node.");
            }
        } catch(err) { console.error(err); }
    });
    // Backup & Restore Logic
    document.getElementById('open-backup-modal-btn').addEventListener('click', () => {
        document.getElementById('backup-modal').style.display = 'flex';
    });
    
    document.getElementById('close-backup-modal').addEventListener('click', () => {
        document.getElementById('backup-modal').style.display = 'none';
    });

    document.getElementById('download-backup-btn').addEventListener('click', async () => {
        const token = localStorage.getItem('token');
        try {
            const res = await fetch('/api/backup', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'cheragh_backup.sqlite';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
            } else {
                alert("Failed to download backup.");
            }
        } catch (err) {
            console.error(err);
        }
    });

    document.getElementById('restore-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('restore-file');
        if (!fileInput.files.length) return;
        
        const file = fileInput.files[0];
        const formData = new FormData();
        formData.append('file', file);
        
        const btn = document.getElementById('restore-submit-btn');
        btn.innerText = "Restoring...";
        btn.disabled = true;

        const token = localStorage.getItem('token');
        try {
            const res = await fetch('/api/restore', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });
            
            if (res.ok) {
                alert("Database restored successfully! Reloading panel...");
                window.location.reload();
            } else {
                const errText = await res.text();
                alert("Restore failed: " + errText);
                btn.innerText = "Upload and Restore";
                btn.disabled = false;
            }
        } catch (err) {
            console.error(err);
            alert("An error occurred during restore.");
            btn.innerText = "Upload and Restore";
            btn.disabled = false;
        }
    });

    
    const deployCustomFields = document.getElementById('deploy-custom-fields');
    deployKharejSelect.addEventListener('change', () => {
        if (deployKharejSelect.value === 'custom') {
            deployCustomFields.style.display = 'block';
        } else {
            deployCustomFields.style.display = 'none';
        }
    });

    const saveNodeCheckbox = document.getElementById('save-node-checkbox');
    const saveNodeNameGroup = document.getElementById('save-node-name-group');
    saveNodeCheckbox.addEventListener('change', () => {
        if (saveNodeCheckbox.checked) {
            saveNodeNameGroup.style.display = 'block';
        } else {
            saveNodeNameGroup.style.display = 'none';
        }
    });

    // Nodes Modal
    document.getElementById('manage-nodes-btn').addEventListener('click', () => {
        loadNodes();
        document.getElementById('nodes-modal').style.display = 'flex';
    });
    
    document.getElementById('close-nodes-modal').addEventListener('click', () => {
        document.getElementById('nodes-modal').style.display = 'none';
    });

    // SSH Deploy Form Submit
    const deployForm = document.getElementById('deploy-tunnel-form');
    deployForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('deploy-tunnel-id').value;
        const iranIdVal = document.getElementById('deploy-iran-select').value;
        const kharejIdVal = document.getElementById('deploy-kharej-select').value;
        
        if (!iranIdVal) {
            alert("Iran Node is required!");
            return;
        }

        const payload = {
            iran_node_id: parseInt(iranIdVal)
        };

        if (kharejIdVal !== 'custom') {
            payload.kharej_node_id = parseInt(kharejIdVal);
        } else {
            payload.host = document.getElementById('ssh-host').value;
            payload.port = parseInt(document.getElementById('ssh-port').value);
            payload.username = document.getElementById('ssh-user').value;
            payload.password = document.getElementById('ssh-password').value || null;
            payload.private_key = document.getElementById('ssh-key').value || null;
            payload.save_node = document.getElementById('save-node-checkbox').checked;
            payload.node_name = document.getElementById('save-node-name').value || null;
            payload.role = "kharej";
        }

        document.getElementById('deploy-modal').style.display = 'none';
        alert("SSH Auto-Deployment task initiated in background. Check tunnel status shortly!");

        try {
            const res = await apiFetch(`/api/tunnels/${id}/deploy`, {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                setTimeout(loadTunnels, 1500);
            } else {
                const errText = await res.text();
                alert("Failed to start deploy: " + errText);
            }
        } catch (err) {
            console.error(err);
        }
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

    // Load initial data
    loadTunnels();
    loadStats();
    loadNodes();

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
                        <button class="btn btn-secondary" style="background: rgba(168, 85, 247, 0.15); color: #a855f7;" onclick="showTelemetry(${t.id}, '${t.name}')">Telemetry</button>
                        <button class="btn btn-secondary" style="background: rgba(0, 240, 255, 0.15); color: var(--color-cyan);" onclick="showEditModal(${t.id})">Edit</button>
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

async function loadNodes() {
    try {
        const res = await apiFetch('/api/nodes');
        if (res && res.ok) {
            const nodes = await res.json();
            const tbody = document.getElementById('nodes-body');
            tbody.innerHTML = '';
            
            const iranSelect = document.getElementById('deploy-iran-select');
            const kharejSelect = document.getElementById('deploy-kharej-select');
            
            iranSelect.innerHTML = '<option value="" disabled selected>-- Select an Iran Node --</option>';
            kharejSelect.innerHTML = '<option value="custom">-- Custom Node (Enter details below) --</option>';

            nodes.forEach(n => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${n.name}</td>
                    <td>${n.host}</td>
                    <td>${n.port}</td>
                    <td>${n.username}</td>
                    <td>
                        <button class="btn btn-secondary btn-small" onclick="deleteNode(${n.id})">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);

                if (n.role === 'iran' || n.role === 'both') {
                    const opt = document.createElement('option');
                    opt.value = n.id;
                    opt.innerText = `${n.name} (${n.host})`;
                    iranSelect.appendChild(opt);
                }
                if (n.role === 'kharej' || n.role === 'both') {
                    const opt = document.createElement('option');
                    opt.value = n.id;
                    opt.innerText = `${n.name} (${n.host})`;
                    kharejSelect.appendChild(opt);
                }
            });
        }
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

async function deleteNode(id) {
    if (!confirm("Are you sure you want to delete this saved node?")) return;
    try {
        const res = await apiFetch(`/api/nodes/${id}`, { method: 'DELETE' });
        if (res && res.ok) {
            loadNodes();
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

async function showEditModal(id) {
    try {
        const res = await apiFetch(`/api/tunnels/${id}`);
        if (!res || !res.ok) return;
        const t = await res.json();
        
        document.getElementById('edit-tunnel-id').value = t.id;
        document.getElementById('edit-tunnel-name').value = t.name;
        document.getElementById('edit-tunnel-protocol').value = t.protocol;
        document.getElementById('edit-iran-port').value = t.iran_port;
        document.getElementById('edit-control-port').value = t.control_port;
        document.getElementById('edit-kharej-port').value = t.kharej_port;
        document.getElementById('edit-backup-ips').value = t.backup_ips || '';
        
        let initialOpts = null;
        if (t.transport_options) {
            try { initialOpts = JSON.parse(t.transport_options); } catch (e) {}
        }
        renderDynamicOptions(t.protocol, 'edit-dynamic-options-container', initialOpts);
        document.getElementById('edit-tunnel-token').value = t.token;
        document.getElementById('edit-decoy-url').value = t.decoy_url || '';
        if (window.toggleDecoyVisibility) {
            window.toggleDecoyVisibility(t.protocol, 'edit-decoy-group');
        }
        
        document.getElementById('edit-modal').style.display = 'flex';
    } catch (err) {
        console.error(err);
    }
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
window.deleteNode = deleteNode;
window.showNodeCommand = showNodeCommand;
window.showEditModal = showEditModal;
window.showDeployModal = showDeployModal;

// Edit form submit & token helpers
document.addEventListener('DOMContentLoaded', () => {
    const editModal = document.getElementById('edit-modal');
    const editForm = document.getElementById('edit-tunnel-form');

    // Close edit modal
    document.getElementById('close-edit-modal').addEventListener('click', () => {
        editModal.style.display = 'none';
    });

    const editProtoSelect = document.getElementById('edit-tunnel-protocol');
    editProtoSelect.addEventListener('change', () => {
        renderDynamicOptions(editProtoSelect.value, 'edit-dynamic-options-container');
        if (window.toggleDecoyVisibility) {
            window.toggleDecoyVisibility(editProtoSelect.value, 'edit-decoy-group');
        }
    });

    // Generate token in edit modal
    document.getElementById('edit-gen-token-btn').addEventListener('click', () => {
        const randToken = Array.from({length: 10}, () => Math.random().toString(36).charAt(2).toUpperCase()).join('');
        document.getElementById('edit-tunnel-token').value = randToken;
    });

    // Handle Edit Submit
    editForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('edit-tunnel-id').value;
        const payload = {
            id: parseInt(id),
            name: document.getElementById('edit-tunnel-name').value,
            protocol: document.getElementById('edit-tunnel-protocol').value,
            iran_port: parseInt(document.getElementById('edit-iran-port').value),
            control_port: parseInt(document.getElementById('edit-control-port').value),
            kharej_port: parseInt(document.getElementById('edit-kharej-port').value),
            token: document.getElementById('edit-tunnel-token').value,
            decoy_url: DECOY_PROTOCOLS.includes(document.getElementById('edit-tunnel-protocol').value)
                ? document.getElementById('edit-decoy-url').value || "google.com"
                : null,
            transport_options: extractDynamicOptions('edit-dynamic-options-container'),
            backup_ips: document.getElementById('edit-backup-ips').value || null,
            status: "inactive",
            stats_rx: 0,
            stats_tx: 0,
            stats_speed_rx: 0,
            stats_speed_tx: 0
        };

        try {
            const res = await apiFetch(`/api/tunnels/${id}`, {
                method: 'PUT',
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                editModal.style.display = 'none';
                loadTunnels();
            } else if (res) {
                const errMsg = await res.text();
                alert(errMsg || "Failed to update tunnel configuration");
            }
        } catch (err) {
            console.error(err);
        }
    });
});

const PROTOCOL_OPTIONS_SCHEMA = {
    "photon": [
        { name: "mtu", label: "MTU (Max Transmission Unit)", type: "number", default: 1350 },
        { name: "nodelay", label: "TCP NoDelay", type: "checkbox", default: true }
    ],
    "mirage": [
        { name: "sni", label: "SNI (Server Name Indication)", type: "text", default: "www.microsoft.com" },
        { name: "fingerprint", label: "uTLS Fingerprint", type: "select", options: ["chrome", "firefox", "safari", "random"], default: "chrome" }
    ],
    "hysteria": [
        { name: "up_mbps", label: "Upload Speed (Mbps)", type: "number", default: 100 },
        { name: "down_mbps", label: "Download Speed (Mbps)", type: "number", default: 100 }
    ],
    "aura": [
        { name: "host", label: "HTTP Host Header", type: "text", default: "bing.com" }
    ],
    "nova": [
        { name: "host", label: "TLS Host Header", type: "text", default: "cloudflare.com" }
    ]
};

function renderDynamicOptions(protocol, containerId, initialData = null) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';
    
    const schema = PROTOCOL_OPTIONS_SCHEMA[protocol];
    if (!schema) return;
    
    schema.forEach(field => {
        const group = document.createElement('div');
        group.className = 'form-group';
        
        const label = document.createElement('label');
        label.innerText = field.label;
        group.appendChild(label);
        
        let value = initialData && initialData[field.name] !== undefined ? initialData[field.name] : field.default;
        
        if (field.type === 'select') {
            const select = document.createElement('select');
            select.dataset.name = field.name;
            select.dataset.type = field.type;
            field.options.forEach(opt => {
                const option = document.createElement('option');
                option.value = opt;
                option.innerText = opt;
                if (opt === value) option.selected = true;
                select.appendChild(option);
            });
            group.appendChild(select);
        } else if (field.type === 'checkbox') {
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.dataset.name = field.name;
            input.dataset.type = field.type;
            if (value) input.checked = true;
            group.appendChild(input);
        } else {
            const input = document.createElement('input');
            input.type = field.type;
            input.dataset.name = field.name;
            input.dataset.type = field.type;
            input.value = value;
            group.appendChild(input);
        }
        
        container.appendChild(group);
    });
}

function extractDynamicOptions(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return null;
    
    const elements = container.querySelectorAll('[data-name]');
    if (elements.length === 0) return null;
    
    const opts = {};
    elements.forEach(el => {
        const name = el.dataset.name;
        if (el.dataset.type === 'checkbox') {
            opts[name] = el.checked;
        } else if (el.dataset.type === 'number') {
            opts[name] = parseInt(el.value);
        } else {
            opts[name] = el.value;
        }
    });
    
    return JSON.stringify(opts);
}

let telemetryChartInstance = null;
let telemetryInterval = null;

async function showTelemetry(id, name) {
    const section = document.getElementById('telemetry-section');
    const title = document.getElementById('telemetry-title');
    
    title.innerText = `Telemetry History: ${name}`;
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth' });
    
    // Clear any active interval first
    if (telemetryInterval) {
        clearInterval(telemetryInterval);
    }
    
    // Initial fetch
    await updateTelemetryChart(id);
    
    // Auto-update every 10 seconds
    telemetryInterval = setInterval(() => {
        updateTelemetryChart(id);
    }, 10000);
}

async function updateTelemetryChart(id) {
    try {
        const res = await apiFetch(`/api/tunnels/${id}/telemetry`);
        if (!res || !res.ok) return;
        const logs = await res.json();
        
        const labels = logs.map(l => {
            const date = new Date(l.timestamp * 1000);
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        });
        const rttData = logs.map(l => l.rtt_ms >= 999 ? null : l.rtt_ms);
        const lossData = logs.map(l => l.packet_loss);
        
        const ctx = document.getElementById('telemetry-chart').getContext('2d');
        
        if (telemetryChartInstance) {
            telemetryChartInstance.data.labels = labels;
            telemetryChartInstance.data.datasets[0].data = rttData;
            telemetryChartInstance.data.datasets[1].data = lossData;
            telemetryChartInstance.update();
        } else {
            telemetryChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'RTT Latency (ms)',
                            data: rttData,
                            borderColor: '#00f0ff',
                            backgroundColor: 'rgba(0, 240, 255, 0.1)',
                            borderWidth: 2,
                            tension: 0.3,
                            yAxisID: 'y'
                        },
                        {
                            label: 'Packet Loss (%)',
                            data: lossData,
                            borderColor: '#ff3366',
                            backgroundColor: 'rgba(255, 51, 102, 0.1)',
                            borderWidth: 2,
                            tension: 0.3,
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            title: {
                                display: true,
                                text: 'RTT (ms)',
                                color: '#fff'
                            },
                            ticks: { color: '#ccc' },
                            grid: { color: 'rgba(255, 255, 255, 0.05)' }
                        },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            title: {
                                display: true,
                                text: 'Loss (%)',
                                color: '#fff'
                            },
                            ticks: { color: '#ccc' },
                            grid: { drawOnChartArea: false },
                            min: 0,
                            max: 100
                        },
                        x: {
                            ticks: { color: '#ccc' },
                            grid: { color: 'rgba(255, 255, 255, 0.05)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: { color: '#fff' }
                        }
                    }
                }
            });
        }
    } catch (err) {
        console.error(err);
    }
}

// Add close button listener
document.addEventListener('DOMContentLoaded', () => {
    const closeBtn = document.getElementById('close-telemetry-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            document.getElementById('telemetry-section').style.display = 'none';
            if (telemetryInterval) {
                clearInterval(telemetryInterval);
                telemetryInterval = null;
            }
        });
    }
});

