const ZengoboxModule = {
    zbLoading: true,
    zbStatus: null,
    zbConfig: null,
    zbSysinfo: null,
    zbApps: [],
    zbAppFilter: '',
    zbShowSystemApps: false,

    // --- daemon control ---
    zbActionBusy: false,

    // --- setup wizard ---
    zbShowSetup: false,
    zbSetupCore: 'all',
    zbSetupVersion: '',
    zbSetupDashboard: 'none',
    zbSetupRunning: false,
    zbSetupLog: '',
    zbSetupTimer: null,
    zbSetupDone: false,
    zbSetupFailed: false,

    // --- accounts manager ---
    zbAcctFile: 'AKUN-ID',
    zbAcctCore: 'clash',
    zbAcctText: '',
    zbAcctList: [],
    zbLinkInput: '',
    zbAcctBusy: false,
    zbEditAll: false,
    zbEditAllText: '',

    // --- live logs ---
    zbLogs: [],
    zbLogsTimer: null,
    zbLogsOn: false,
    zbAutoScroll: true,

    async fetchZengoboxStatus() {
        try {
            const res = await fetch('/api/zengobox/status');
            if (res.ok) this.zbStatus = await res.json();
        } catch (e) {}
    },

    async fetchZengoboxConfig() {
        try {
            const res = await fetch('/api/zengobox/config');
            if (res.ok) this.zbConfig = await res.json();
        } catch (e) {}
    },

    async fetchZengoboxSysinfo() {
        try {
            const res = await fetch('/api/zengobox/sysinfo');
            if (res.ok) this.zbSysinfo = await res.json();
        } catch (e) {}
    },

    async fetchZengoboxApps() {
        try {
            const res = await fetch('/api/zengobox/apps');
            if (res.ok) {
                const data = await res.json();
                this.zbApps = data.apps || [];
            }
        } catch (e) {}
    },

    async fetchZengobox() {
        this.zbLoading = true;
        await Promise.all([
            this.fetchZengoboxStatus(),
            this.fetchZengoboxConfig(),
            this.fetchZengoboxSysinfo(),
            this.fetchZengoboxApps(),
        ]);
        this.zbLoading = false;
    },

    zbFilteredApps() {
        const f = (this.zbAppFilter || '').toLowerCase();
        return this.zbApps.filter(a => {
            if (!this.zbShowSystemApps && a.system) return false;
            if (!f) return true;
            const pkg = (a.package || '').toLowerCase();
            const label = (a.label || '').toLowerCase();
            return pkg.includes(f) || label.includes(f);
        });
    },

    zbToggleChip(on) {
        return on
            ? 'text-green-400 bg-green-500/10 border-green-500/30'
            : 'text-gray-500 bg-white/5 border-white/10';
    },

    // --- daemon control ---

    async zbControl(action) {
        if (this.zbActionBusy) return;
        this.zbActionBusy = true;
        try {
            const res = await fetch('/api/zengobox/' + action, { method: 'POST' });
            const data = await res.json().catch(() => ({}));
            if (data && data.needs_setup) {
                this.zbShowSetup = true;
            }
            await this.fetchZengoboxStatus();
        } catch (e) {}
        this.zbActionBusy = false;
    },

    // --- setup wizard ---

    zbDashboardOptions() {
        return [
            { v: 'https://github.com/Zephyruso/zashboard/archive/gh-pages.zip', t: 'Zashboard (modern, recommended)' },
            { v: 'https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip', t: 'MetaCubeXD' },
            { v: 'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip', t: 'Yacd-meta' },
            { v: 'https://github.com/taamarin/yacd-meta/archive/gh-pages.zip', t: 'Yacd-meta (Taamarin)' },
            { v: 'https://github.com/haishanh/yacd/archive/gh-pages.zip', t: 'Yacd' },
            { v: 'https://github.com/Dreamacro/clash-dashboard/archive/gh-pages.zip', t: 'Clash-Dashboard (classic)' },
            { v: 'none', t: 'Skip (no dashboard)' },
        ];
    },

    async zbStartSetup() {
        if (this.zbSetupRunning) return;
        this.zbSetupRunning = true;
        this.zbSetupDone = false;
        this.zbSetupFailed = false;
        this.zbSetupLog = 'Starting...\n';
        try {
            const res = await fetch('/api/zengobox/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    core: this.zbSetupCore,
                    version: this.zbSetupVersion,
                    dashboard: this.zbSetupDashboard,
                }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.zbPollSetupLog();
        } catch (e) {
            this.zbSetupLog += '[SETUP_FAILED] ' + e.message + '\n';
            this.zbSetupRunning = false;
            this.zbSetupFailed = true;
        }
    },

    async zbPollSetupLog() {
        if (this.zbSetupTimer) clearInterval(this.zbSetupTimer);
        const tick = async () => {
            try {
                const res = await fetch('/api/zengobox/setup_log');
                const text = await res.text();
                this.zbSetupLog = text;
                const el = document.getElementById('zb-setup-log');
                if (el && this.zbAutoScroll) el.scrollTop = el.scrollHeight;
                if (text.includes('Setup complete!')) {
                    clearInterval(this.zbSetupTimer);
                    this.zbSetupTimer = null;
                    this.zbSetupRunning = false;
                    this.zbSetupDone = true;
                    await this.fetchZengobox();
                } else if (text.includes('[SETUP_FAILED]')) {
                    clearInterval(this.zbSetupTimer);
                    this.zbSetupTimer = null;
                    this.zbSetupRunning = false;
                    this.zbSetupFailed = true;
                }
            } catch (e) {}
        };
        await tick();
        this.zbSetupTimer = setInterval(tick, 1000);
    },

    zbStopSetupPoll() {
        if (this.zbSetupTimer) {
            clearInterval(this.zbSetupTimer);
            this.zbSetupTimer = null;
        }
        this.zbSetupRunning = false;
    },

    // --- accounts manager ---

    zbAcctExt() {
        return (this.zbAcctCore === 'clash') ? 'yaml' : 'json';
    },

    zbAcctFileName() {
        return this.zbAcctFile + '.' + this.zbAcctExt();
    },

    async zbLoadAccounts() {
        try {
            const res = await fetch('/api/zengobox/accounts?file=' + encodeURIComponent(this.zbAcctFileName()) +
                '&core=' + encodeURIComponent(this.zbAcctCore) + '&t=' + Date.now(), { cache: 'no-store' });
            this.zbAcctText = res.ok ? await res.text() : '';
            this.zbParseAcctList();
        } catch (e) {
            this.zbAcctText = '';
            this.zbAcctList = [];
        }
    },

    zbParseAcctList() {
        const list = [];
        const text = this.zbAcctText || '';
        if (this.zbAcctCore === 'clash') {
            for (const line of text.split('\n')) {
                const m = line.trim().match(/^-\s*name:\s*(.+)$/);
                if (m) list.push(m[1].replace(/^['"]|['"]$/g, ''));
            }
        } else {
            try {
                const t = text.trim();
                if (t) {
                    const parsed = JSON.parse(t);
                    const arr = Array.isArray(parsed) ? parsed : (parsed.outbounds || []);
                    for (const o of arr) {
                        if (o && o.tag) list.push(String(o.tag));
                    }
                }
            } catch (e) {}
        }
        this.zbAcctList = list;
    },

    async zbSaveAccounts() {
        if (this.zbAcctBusy) return;
        this.zbAcctBusy = true;
        try {
            const res = await fetch('/api/zengobox/accounts?file=' + encodeURIComponent(this.zbAcctFileName()) +
                '&core=' + encodeURIComponent(this.zbAcctCore), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: this.zbAcctText }),
            });
            if (!res.ok) throw new Error(await res.text());
            this.zbParseAcctList();
        } catch (e) {}
        this.zbAcctBusy = false;
    },

    async zbConvertAndSave() {
        const link = (this.zbLinkInput || '').trim();
        if (!link || this.zbAcctBusy) return;
        this.zbAcctBusy = true;
        try {
            const convRes = await fetch('/api/zengobox/accounts/convert?core=' + encodeURIComponent(this.zbAcctCore), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ link }),
            });
            if (!convRes.ok) throw new Error(await convRes.text());
            const parsed = await convRes.json();
            let text = this.zbAcctText || '';
            if (parsed.yaml) {
                // clash: append YAML block
                if (!text.includes('proxies:')) text = 'proxies:\n' + text;
                text = text.trim() + '\n' + parsed.yaml;
            } else {
                // sing-box: append outbound object
                const t = text.trim();
                let obj = { outbounds: [] };
                let arr = [];
                if (t.startsWith('{') || t.startsWith('[')) {
                    try {
                        const p = JSON.parse(t);
                        arr = Array.isArray(p) ? p : (p.outbounds || []);
                        obj = Array.isArray(p) ? p : { outbounds: arr };
                    } catch (e) {}
                }
                arr.push(parsed);
                if (Array.isArray(obj)) obj = arr;
                else obj.outbounds = arr;
                text = JSON.stringify(obj, null, 2);
            }
            this.zbAcctText = text;
            await this.zbSaveAccounts();
            this.zbLinkInput = '';
        } catch (e) {}
        this.zbAcctBusy = false;
    },

    async zbDeleteAccount(name) {
        if (!confirm('Delete "' + name + '"?')) return;
        const text = this.zbAcctText || '';
        let out = text;
        if (this.zbAcctCore === 'clash') {
            // remove the "- name: X" block (up to the next "- name:" or EOF)
            const lines = text.split('\n');
            const keep = [];
            let skip = false;
            for (const line of lines) {
                const m = line.trim().match(/^-\s*name:\s*(.+)$/);
                if (m) {
                    skip = (m[1].replace(/^['"]|['"]$/g, '') === name);
                    if (!skip) keep.push(line);
                    continue;
                }
                if (!skip) keep.push(line);
            }
            out = keep.join('\n');
        } else {
            try {
                const p = JSON.parse(text);
                const arr = Array.isArray(p) ? p : (p.outbounds || []);
                const filtered = arr.filter(o => String(o && o.tag) !== name);
                out = JSON.stringify(Array.isArray(p) ? filtered : { outbounds: filtered }, null, 2);
            } catch (e) { return; }
        }
        this.zbAcctText = out;
        await this.zbSaveAccounts();
    },

    zbOpenEditAll() {
        this.zbEditAllText = this.zbAcctText;
        this.zbEditAll = true;
    },

    async zbApplyEditAll() {
        this.zbAcctText = this.zbEditAllText;
        this.zbEditAll = false;
        await this.zbSaveAccounts();
    },

    // --- live logs ---

    async zbLoadLogs() {
        try {
            const res = await fetch('/api/zengobox/logs');
            if (res.ok) {
                const data = await res.json();
                this.zbLogs = data.logs || [];
                const el = document.getElementById('zb-log-view');
                if (el && this.zbAutoScroll) el.scrollTop = el.scrollHeight;
            }
        } catch (e) {}
    },

    zbToggleLogs() {
        if (this.zbLogsOn) {
            if (this.zbLogsTimer) clearInterval(this.zbLogsTimer);
            this.zbLogsTimer = null;
            this.zbLogsOn = false;
        } else {
            this.zbLogsOn = true;
            this.zbLoadLogs();
            this.zbLogsTimer = setInterval(() => this.zbLoadLogs(), 2000);
        }
    },
};
