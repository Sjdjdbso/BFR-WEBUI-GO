const ZengoboxModule = {
    zbLoading: true,
    zbStatus: null,
    zbConfig: null,
    zbSysinfo: null,
    zbApps: [],
    zbAppFilter: '',
    zbShowSystemApps: false,

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
};
