document.addEventListener('DOMContentLoaded', () => {
    const totalVisitsElem = document.getElementById('totalVisits');
    const uniqueIpsElem = document.getElementById('uniqueIps');
    const todayVisitsElem = document.getElementById('todayVisits');
    const logsTableBody = document.getElementById('logsTableBody');
    const refreshBtn = document.getElementById('refreshBtn');
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    const searchInput = document.getElementById('searchInput');

    let allLogs = [];

    // Fetch KPI Stats
    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            totalVisitsElem.textContent = data.total_visits || 0;
            uniqueIpsElem.textContent = data.unique_ips || 0;
            todayVisitsElem.textContent = data.today_visits || 0;
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    }

    // Fetch Access Logs
    async function fetchLogs() {
        try {
            const res = await fetch('/api/logs');
            allLogs = await res.json();
            renderLogsTable(allLogs);
        } catch (err) {
            console.error('Error fetching logs:', err);
            logsTableBody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: var(--danger);">Failed to load connection logs.</td></tr>`;
        }
    }

    // Render Logs in Table
    function renderLogsTable(logs) {
        if (!logs || logs.length === 0) {
            logsTableBody.innerHTML = `<tr><td colspan="7" class="text-center">No connection logs recorded yet.</td></tr>`;
            return;
        }

        logsTableBody.innerHTML = logs.map(log => `
            <tr>
                <td>#${log.id}</td>
                <td><strong>${escapeHtml(log.visitor_name || 'Anonymous')}</strong></td>
                <td><strong class="monospace">${escapeHtml(log.ip_address)}</strong></td>
                <td><span class="monospace" title="${escapeHtml(log.user_agent)}">${truncateText(log.user_agent, 35)}</span></td>
                <td><code>${escapeHtml(log.path || '/')}</code></td>
                <td>${escapeHtml(log.timestamp)}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="copyToClipboard('${escapeHtml(log.ip_address)}')">
                        📋 Copy IP
                    </button>
                </td>
            </tr>
        `).join('');
    }

    function truncateText(str, maxLen) {
        if (!str) return 'Unknown';
        return str.length > maxLen ? str.substring(0, maxLen) + '...' : str;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert(`Copied IP: ${text}`);
        });
    };

    // Search Filter
    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = allLogs.filter(log => 
            (log.visitor_name && log.visitor_name.toLowerCase().includes(query)) ||
            (log.ip_address && log.ip_address.toLowerCase().includes(query)) ||
            (log.user_agent && log.user_agent.toLowerCase().includes(query)) ||
            (log.path && log.path.toLowerCase().includes(query))
        );
        renderLogsTable(filtered);
    });

    // Refresh Data
    refreshBtn.addEventListener('click', () => {
        fetchStats();
        fetchLogs();
    });

    // Clear Logs History
    clearLogsBtn.addEventListener('click', async () => {
        if (confirm('Are you sure you want to clear all access logs from the database?')) {
            try {
                const res = await fetch('/api/logs/clear', { method: 'POST' });
                const result = await res.json();
                alert(result.message);
                fetchStats();
                fetchLogs();
            } catch (err) {
                alert('Failed to clear logs');
            }
        }
    });

    // Initial Load & Auto-Refresh every 5 seconds
    fetchStats();
    fetchLogs();
    setInterval(() => {
        fetchStats();
        fetchLogs();
    }, 5000);
});
