<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface UserInfo {
		username: string;
		uid: number;
		gid: number;
		groups: string[];
		is_root: boolean;
		home_dir: string;
		shell: string;
	}

	interface SecurityScore {
		score: number;
		level: string;
		high_count: number;
		medium_count: number;
		low_count: number;
		critical_count: number;
		total_findings: number;
	}

	interface PermissionBinary {
		path: string;
		permissions: string;
		owner: string;
		risk_level: string;
		description: string;
		exploit_hint: string;
	}

	interface CapabilityInfo {
		capability: string;
		binary: string;
		risk_level: string;
		description: string;
		exploit_hint: string;
	}

	interface CronJobInfo {
		schedule: string;
		command: string;
		user: string;
		risk_level: string;
		description: string;
	}

	interface WritablePath {
		path: string;
		permissions: string;
		risk_level: string;
		description: string;
		exploit_hint: string;
	}

	interface VulnerableService {
		name: string;
		version: string;
		config_path: string;
		risk_level: string;
		description: string;
		exploit_hint: string;
	}

	interface KernelExploit {
		kernel_version: string;
		cve: string;
		name: string;
		risk_level: string;
		description: string;
	}

	interface DockerIssue {
		issue_type: string;
		description: string;
		risk_level: string;
		exploit_hint: string;
	}

	interface Misconfiguration {
		category: string;
		description: string;
		risk_level: string;
		recommendation: string;
	}

	interface PrivilegeEscResult {
		success: boolean;
		target: string;
		os_type: string;
		current_user: UserInfo;
		suid_binaries: PermissionBinary[];
		sgid_binaries: PermissionBinary[];
		capabilities: CapabilityInfo[];
		cron_jobs: CronJobInfo[];
		writable_paths: WritablePath[];
		vulnerable_services: VulnerableService[];
		kernel_exploits: KernelExploit[];
		docker_issues: DockerIssue[];
		misconfigurations: Misconfiguration[];
		security_score: SecurityScore;
		summary: string;
	}

	let target = $state('');
	let osType = $state('linux');
	let checkSuid = $state(true);
	let checkSgid = $state(true);
	let checkCapabilities = $state(true);
	let checkCron = $state(true);
	let checkWritable = $state(true);
	let checkServices = $state(true);
	let checkKernel = $state(true);
	let checkDocker = $state(true);
	let result: PrivilegeEscResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let exportFormat = $state('json');
	let exporting = $state(false);

	let historyComponent: ToolHistory = $state(null!);

	let criticalFindings = $derived.by(() => {
		if (!result) return [];
		const all: { type: string; risk: string; desc: string; hint: string }[] = [];
		result.suid_binaries.filter(b => b.risk_level === 'critical').forEach(b => all.push({ type: 'SUID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.sgid_binaries.filter(b => b.risk_level === 'critical').forEach(b => all.push({ type: 'SGID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.capabilities.filter(c => c.risk_level === 'critical').forEach(c => all.push({ type: $tr('privilegeEscCheck.tabs.capabilities'), risk: c.risk_level, desc: `${c.capability} (${c.binary}): ${c.description}`, hint: c.exploit_hint }));
		result.writable_paths.filter(w => w.risk_level === 'critical').forEach(w => all.push({ type: $tr('privilegeEscCheck.tabs.writable'), risk: w.risk_level, desc: `${w.path}: ${w.description}`, hint: w.exploit_hint }));
		result.vulnerable_services.filter(s => s.risk_level === 'critical').forEach(s => all.push({ type: $tr('privilegeEscCheck.tabs.services'), risk: s.risk_level, desc: `${s.name} ${s.version}: ${s.description}`, hint: s.exploit_hint }));
		result.kernel_exploits.filter(k => k.risk_level === 'critical').forEach(k => all.push({ type: $tr('privilegeEscCheck.tabs.kernel'), risk: k.risk_level, desc: `${k.name} (${k.cve}): ${k.description}`, hint: '' }));
		result.docker_issues.filter(d => d.risk_level === 'critical').forEach(d => all.push({ type: 'Docker', risk: d.risk_level, desc: `${d.issue_type}: ${d.description}`, hint: d.exploit_hint }));
		result.misconfigurations.filter(m => m.risk_level === 'critical').forEach(m => all.push({ type: $tr('privilegeEscCheck.tabs.misconfig'), risk: m.risk_level, desc: `${m.category}: ${m.description}`, hint: m.recommendation }));
		return all;
	});

	let highFindings = $derived.by(() => {
		if (!result) return [];
		const all: { type: string; risk: string; desc: string; hint: string }[] = [];
		result.suid_binaries.filter(b => b.risk_level === 'high').forEach(b => all.push({ type: 'SUID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.sgid_binaries.filter(b => b.risk_level === 'high').forEach(b => all.push({ type: 'SGID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.capabilities.filter(c => c.risk_level === 'high').forEach(c => all.push({ type: $tr('privilegeEscCheck.tabs.capabilities'), risk: c.risk_level, desc: `${c.capability} (${c.binary}): ${c.description}`, hint: c.exploit_hint }));
		result.writable_paths.filter(w => w.risk_level === 'high').forEach(w => all.push({ type: $tr('privilegeEscCheck.tabs.writable'), risk: w.risk_level, desc: `${w.path}: ${w.description}`, hint: w.exploit_hint }));
		result.vulnerable_services.filter(s => s.risk_level === 'high').forEach(s => all.push({ type: $tr('privilegeEscCheck.tabs.services'), risk: s.risk_level, desc: `${s.name} ${s.version}: ${s.description}`, hint: s.exploit_hint }));
		result.kernel_exploits.filter(k => k.risk_level === 'high').forEach(k => all.push({ type: $tr('privilegeEscCheck.tabs.kernel'), risk: k.risk_level, desc: `${k.name} (${k.cve}): ${k.description}`, hint: '' }));
		result.docker_issues.filter(d => d.risk_level === 'high').forEach(d => all.push({ type: 'Docker', risk: d.risk_level, desc: `${d.issue_type}: ${d.description}`, hint: d.exploit_hint }));
		result.misconfigurations.filter(m => m.risk_level === 'high').forEach(m => all.push({ type: $tr('privilegeEscCheck.tabs.misconfig'), risk: m.risk_level, desc: `${m.category}: ${m.description}`, hint: m.recommendation }));
		return all;
	});

	let mediumFindings = $derived.by(() => {
		if (!result) return [];
		const all: { type: string; risk: string; desc: string; hint: string }[] = [];
		result.suid_binaries.filter(b => b.risk_level === 'medium').forEach(b => all.push({ type: 'SUID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.sgid_binaries.filter(b => b.risk_level === 'medium').forEach(b => all.push({ type: 'SGID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.capabilities.filter(c => c.risk_level === 'medium').forEach(c => all.push({ type: $tr('privilegeEscCheck.tabs.capabilities'), risk: c.risk_level, desc: `${c.capability} (${c.binary}): ${c.description}`, hint: c.exploit_hint }));
		result.writable_paths.filter(w => w.risk_level === 'medium').forEach(w => all.push({ type: $tr('privilegeEscCheck.tabs.writable'), risk: w.risk_level, desc: `${w.path}: ${w.description}`, hint: w.exploit_hint }));
		result.vulnerable_services.filter(s => s.risk_level === 'medium').forEach(s => all.push({ type: $tr('privilegeEscCheck.tabs.services'), risk: s.risk_level, desc: `${s.name} ${s.version}: ${s.description}`, hint: s.exploit_hint }));
		result.kernel_exploits.filter(k => k.risk_level === 'medium').forEach(k => all.push({ type: $tr('privilegeEscCheck.tabs.kernel'), risk: k.risk_level, desc: `${k.name} (${k.cve}): ${k.description}`, hint: '' }));
		result.docker_issues.filter(d => d.risk_level === 'medium').forEach(d => all.push({ type: 'Docker', risk: d.risk_level, desc: `${d.issue_type}: ${d.description}`, hint: d.exploit_hint }));
		result.misconfigurations.filter(m => m.risk_level === 'medium').forEach(m => all.push({ type: $tr('privilegeEscCheck.tabs.misconfig'), risk: m.risk_level, desc: `${m.category}: ${m.description}`, hint: m.recommendation }));
		return all;
	});

	let lowFindings = $derived.by(() => {
		if (!result) return [];
		const all: { type: string; risk: string; desc: string; hint: string }[] = [];
		result.suid_binaries.filter(b => b.risk_level === 'low').forEach(b => all.push({ type: 'SUID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.sgid_binaries.filter(b => b.risk_level === 'low').forEach(b => all.push({ type: 'SGID', risk: b.risk_level, desc: `${b.path}: ${b.description}`, hint: b.exploit_hint }));
		result.capabilities.filter(c => c.risk_level === 'low').forEach(c => all.push({ type: $tr('privilegeEscCheck.tabs.capabilities'), risk: c.risk_level, desc: `${c.capability} (${c.binary}): ${c.description}`, hint: c.exploit_hint }));
		result.writable_paths.filter(w => w.risk_level === 'low').forEach(w => all.push({ type: $tr('privilegeEscCheck.tabs.writable'), risk: w.risk_level, desc: `${w.path}: ${w.description}`, hint: w.exploit_hint }));
		result.vulnerable_services.filter(s => s.risk_level === 'low').forEach(s => all.push({ type: $tr('privilegeEscCheck.tabs.services'), risk: s.risk_level, desc: `${s.name} ${s.version}: ${s.description}`, hint: s.exploit_hint }));
		result.docker_issues.filter(d => d.risk_level === 'low').forEach(d => all.push({ type: 'Docker', risk: d.risk_level, desc: `${d.issue_type}: ${d.description}`, hint: d.exploit_hint }));
		result.misconfigurations.filter(m => m.risk_level === 'low').forEach(m => all.push({ type: $tr('privilegeEscCheck.tabs.misconfig'), risk: m.risk_level, desc: `${m.category}: ${m.description}`, hint: m.recommendation }));
		return all;
	});

	let scoreColor = $derived.by(() => {
		if (!result) return '#a855f7';
		const s = result.security_score.score;
		if (s >= 90) return '#22c55e';
		if (s >= 70) return '#3b82f6';
		if (s >= 50) return '#f59e0b';
		if (s >= 25) return '#ef4444';
		return '#dc2626';
	});

	let scoreLevelText = $derived.by(() => {
		if (!result) return '';
		return $tr(`privilegeEscCheck.scoreLevels.${result.security_score.level}`);
	});

	async function startCheck() {
		if (!target.trim()) {
			error = $tr('privilegeEscCheck.error.emptyTarget');
			return;
		}
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<PrivilegeEscResult>('check_privilege_esc_command', {
				config: {
					target: target.trim(),
					check_type: 'local',
					os_type: osType,
					check_suid: checkSuid,
					check_sgid: checkSgid,
					check_capabilities: checkCapabilities,
					check_cron: checkCron,
					check_writable: checkWritable,
					check_services: checkServices,
					check_kernel: checkKernel,
					check_docker: checkDocker
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		target = '';
		result = null;
		error = '';
		activeResultTab = 'overview';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#dc2626';
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			default: return '#6b7280';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(220,38,38,0.15)';
			case 'high': return 'rgba(239,68,68,0.15)';
			case 'medium': return 'rgba(245,158,11,0.15)';
			case 'low': return 'rgba(59,130,246,0.15)';
			default: return 'rgba(107,114,128,0.15)';
		}
	}

	function getSeverityLabel(severity: string): string {
		return $tr(`privilegeEscCheck.severity.${severity}`) || severity;
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({
				directory: true,
				multiple: false,
			});
			if (!savePath) {
				exporting = false;
				return;
			}
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `privilege-esc-${new Date().toISOString().slice(0, 10)}.${ext}`;
			let content: string;
			if (exportFormat === 'csv') {
				const rows = [['Type', 'Risk', 'Description', 'Hint']];
				result.suid_binaries.forEach(b => rows.push(['SUID', b.risk_level, b.description, b.exploit_hint]));
				result.sgid_binaries.forEach(b => rows.push(['SGID', b.risk_level, b.description, b.exploit_hint]));
				result.capabilities.forEach(c => rows.push(['Capability', c.risk_level, c.description, c.exploit_hint]));
				result.writable_paths.forEach(w => rows.push(['Writable', w.risk_level, w.description, w.exploit_hint]));
				result.vulnerable_services.forEach(s => rows.push(['Service', s.risk_level, s.description, s.exploit_hint]));
				result.kernel_exploits.forEach(k => rows.push(['Kernel', k.risk_level, k.description, '']));
				result.docker_issues.forEach(d => rows.push(['Docker', d.risk_level, d.description, d.exploit_hint]));
				result.misconfigurations.forEach(m => rows.push(['Misconfig', m.risk_level, m.description, m.recommendation]));
				content = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
			} else {
				content = JSON.stringify(result, null, 2);
			}
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			const path = `${savePath}/${fileName}`;
			await writeTextFile(path, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔓 {$tr('privilegeEscCheck.title')}</h1>
			<p class="page-subtitle">{$tr('privilegeEscCheck.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('privilegeEscCheck.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('common.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('common.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('privilegeEscCheck.configTitle')}</h2>
					<p class="section-desc">{$tr('privilegeEscCheck.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="pe-target">{$tr('privilegeEscCheck.target')}</label>
						<input id="pe-target" type="text" bind:value={target} placeholder={$tr('privilegeEscCheck.targetPlaceholder')} class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label" for="pe-os">{$tr('privilegeEscCheck.osType')}</label>
						<select id="pe-os" bind:value={osType} class="form-input" disabled={processing}>
							<option value="linux">🐧 Linux</option>
							<option value="macos">🍎 macOS</option>
							<option value="windows">🪟 Windows</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('privilegeEscCheck.checkItems')}</label>
						<div class="check-grid">
							<label class="check-chip {checkSuid ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkSuid} disabled={processing} />
								<span class="check-icon">🔑</span>
								<span>SUID</span>
							</label>
							<label class="check-chip {checkSgid ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkSgid} disabled={processing} />
								<span class="check-icon">🔑</span>
								<span>SGID</span>
							</label>
							<label class="check-chip {checkCapabilities ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCapabilities} disabled={processing} />
								<span class="check-icon">⚡</span>
								<span>{$tr('privilegeEscCheck.tabs.capabilities')}</span>
							</label>
							<label class="check-chip {checkCron ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkCron} disabled={processing} />
								<span class="check-icon">⏰</span>
								<span>Cron</span>
							</label>
							<label class="check-chip {checkWritable ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkWritable} disabled={processing} />
								<span class="check-icon">📝</span>
								<span>{$tr('privilegeEscCheck.tabs.writable')}</span>
							</label>
							<label class="check-chip {checkServices ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkServices} disabled={processing} />
								<span class="check-icon">🔧</span>
								<span>{$tr('privilegeEscCheck.tabs.services')}</span>
							</label>
							<label class="check-chip {checkKernel ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkKernel} disabled={processing} />
								<span class="check-icon">🐧</span>
								<span>{$tr('privilegeEscCheck.tabs.kernel')}</span>
							</label>
							<label class="check-chip {checkDocker ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDocker} disabled={processing} />
								<span class="check-icon">🐳</span>
								<span>Docker</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={startCheck} disabled={processing || !target.trim()}>
							{#if processing}
								<span class="spinner"></span> {$tr('privilegeEscCheck.checking')}
							{:else}
								🔓 {$tr('privilegeEscCheck.startCheck')}
							{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('common.reset')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="error-banner">
						<span class="error-icon">⚠️</span>
						<span>{error}</span>
					</div>
				{:else if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {scoreColor}">
								<span class="score-number" style="color: {scoreColor}">{result.security_score.score}</span>
								<span class="score-max">/100</span>
							</div>
							<div class="score-details">
								<div class="score-level" style="color: {scoreColor}">{scoreLevelText}</div>
								<div class="score-stats">
									<span class="stat-item critical">🔴 {$tr('privilegeEscCheck.severity.critical')}: {result.security_score.critical_count}</span>
									<span class="stat-item high">🟠 {$tr('privilegeEscCheck.severity.high')}: {result.security_score.high_count}</span>
									<span class="stat-item medium">🟡 {$tr('privilegeEscCheck.severity.medium')}: {result.security_score.medium_count}</span>
									<span class="stat-item low">🔵 {$tr('privilegeEscCheck.severity.low')}: {result.security_score.low_count}</span>
								</div>
								<div class="score-total">{$tr('privilegeEscCheck.totalFindings')}: {result.security_score.total_findings}</div>
							</div>
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}⏳{:else}📥{/if} {$tr('common.export')}
								</button>
							</div>
						</div>
					</div>

					<div class="section-card user-section">
						<div class="user-row">
							<div class="user-main">
								<span class="user-icon">{result.current_user.is_root ? '👑' : '👤'}</span>
								<span class="user-name">{result.current_user.username}</span>
								<span class="user-uid">UID:{result.current_user.uid} GID:{result.current_user.gid}</span>
								{#if result.current_user.is_root}
									<span class="root-badge">ROOT</span>
								{/if}
							</div>
							<div class="user-meta">
								<span>🏠 {result.current_user.home_dir}</span>
								<span>🐚 {result.current_user.shell}</span>
							</div>
							{#if result.current_user.groups.length > 0}
								<div class="user-groups">
									{#each result.current_user.groups as g}
										<span class="group-tag">{g}</span>
									{/each}
								</div>
							{/if}
						</div>
					</div>

					<div class="result-tabs">
						<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
							📊 {$tr('privilegeEscCheck.tabs.overview')}
						</button>
						<button class="result-tab {activeResultTab === 'suid' ? 'active' : ''}" onclick={() => activeResultTab = 'suid'}>
							🔑 SUID ({result.suid_binaries.length})
						</button>
						<button class="result-tab {activeResultTab === 'sgid' ? 'active' : ''}" onclick={() => activeResultTab = 'sgid'}>
							🔑 SGID ({result.sgid_binaries.length})
						</button>
						<button class="result-tab {activeResultTab === 'caps' ? 'active' : ''}" onclick={() => activeResultTab = 'caps'}>
							⚡ {$tr('privilegeEscCheck.tabs.capabilities')} ({result.capabilities.length})
						</button>
						<button class="result-tab {activeResultTab === 'cron' ? 'active' : ''}" onclick={() => activeResultTab = 'cron'}>
							⏰ Cron ({result.cron_jobs.length})
						</button>
						<button class="result-tab {activeResultTab === 'writable' ? 'active' : ''}" onclick={() => activeResultTab = 'writable'}>
							📝 {$tr('privilegeEscCheck.tabs.writable')} ({result.writable_paths.length})
						</button>
						<button class="result-tab {activeResultTab === 'services' ? 'active' : ''}" onclick={() => activeResultTab = 'services'}>
							🔧 {$tr('privilegeEscCheck.tabs.services')} ({result.vulnerable_services.length})
						</button>
						<button class="result-tab {activeResultTab === 'kernel' ? 'active' : ''}" onclick={() => activeResultTab = 'kernel'}>
							🐧 {$tr('privilegeEscCheck.tabs.kernel')} ({result.kernel_exploits.length})
						</button>
						<button class="result-tab {activeResultTab === 'docker' ? 'active' : ''}" onclick={() => activeResultTab = 'docker'}>
							🐳 Docker ({result.docker_issues.length})
						</button>
						<button class="result-tab {activeResultTab === 'misconfig' ? 'active' : ''}" onclick={() => activeResultTab = 'misconfig'}>
							⚙️ {$tr('privilegeEscCheck.tabs.misconfig')} ({result.misconfigurations.length})
						</button>
					</div>

					<div class="section-card">
						{#if activeResultTab === 'overview'}
							<div class="findings-overview">
								{#if criticalFindings.length > 0}
									<div class="findings-group critical-group">
										<h3 class="findings-group-title">🔴 {$tr('privilegeEscCheck.severity.critical')} ({criticalFindings.length})</h3>
										{#each criticalFindings as f}
											<div class="finding-card" style="border-left-color: {getSeverityColor(f.risk)}">
												<div class="finding-header">
													<span class="finding-type" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{f.type}</span>
													<span class="finding-severity" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{getSeverityLabel(f.risk)}</span>
												</div>
												<p class="finding-desc">{f.desc}</p>
												{#if f.hint}
													<p class="finding-hint">🎯 {f.hint}</p>
												{/if}
											</div>
										{/each}
									</div>
								{/if}
								{#if highFindings.length > 0}
									<div class="findings-group high-group">
										<h3 class="findings-group-title">🟠 {$tr('privilegeEscCheck.severity.high')} ({highFindings.length})</h3>
										{#each highFindings as f}
											<div class="finding-card" style="border-left-color: {getSeverityColor(f.risk)}">
												<div class="finding-header">
													<span class="finding-type" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{f.type}</span>
													<span class="finding-severity" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{getSeverityLabel(f.risk)}</span>
												</div>
												<p class="finding-desc">{f.desc}</p>
												{#if f.hint}
													<p class="finding-hint">🎯 {f.hint}</p>
												{/if}
											</div>
										{/each}
									</div>
								{/if}
								{#if mediumFindings.length > 0}
									<div class="findings-group medium-group">
										<h3 class="findings-group-title">🟡 {$tr('privilegeEscCheck.severity.medium')} ({mediumFindings.length})</h3>
										{#each mediumFindings as f}
											<div class="finding-card" style="border-left-color: {getSeverityColor(f.risk)}">
												<div class="finding-header">
													<span class="finding-type" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{f.type}</span>
													<span class="finding-severity" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{getSeverityLabel(f.risk)}</span>
												</div>
												<p class="finding-desc">{f.desc}</p>
												{#if f.hint}
													<p class="finding-hint">🎯 {f.hint}</p>
												{/if}
											</div>
										{/each}
									</div>
								{/if}
								{#if lowFindings.length > 0}
									<div class="findings-group low-group">
										<h3 class="findings-group-title">🔵 {$tr('privilegeEscCheck.severity.low')} ({lowFindings.length})</h3>
										{#each lowFindings as f}
											<div class="finding-card" style="border-left-color: {getSeverityColor(f.risk)}">
												<div class="finding-header">
													<span class="finding-type" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{f.type}</span>
													<span class="finding-severity" style="background: {getSeverityBg(f.risk)}; color: {getSeverityColor(f.risk)}">{getSeverityLabel(f.risk)}</span>
												</div>
												<p class="finding-desc">{f.desc}</p>
												{#if f.hint}
													<p class="finding-hint">🎯 {f.hint}</p>
												{/if}
											</div>
										{/each}
									</div>
								{/if}
								{#if result.security_score.total_findings === 0}
									<div class="no-findings">
										<span class="no-findings-icon">✅</span>
										<p>{$tr('privilegeEscCheck.noFindings')}</p>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'suid'}
							<div class="detail-list">
								{#if result.suid_binaries.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.suid_binaries as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<code class="detail-path">{item.path}</code>
												<span class="detail-owner">{item.owner}</span>
											</div>
											<div class="detail-meta">
												<span class="detail-perms">📋 {item.permissions}</span>
											</div>
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'sgid'}
							<div class="detail-list">
								{#if result.sgid_binaries.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.sgid_binaries as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<code class="detail-path">{item.path}</code>
												<span class="detail-owner">{item.owner}</span>
											</div>
											<div class="detail-meta">
												<span class="detail-perms">📋 {item.permissions}</span>
											</div>
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'caps'}
							<div class="detail-list">
								{#if result.capabilities.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.capabilities as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<code class="detail-path">{item.capability}</code>
											</div>
											<p class="detail-desc">📁 {item.binary}</p>
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'cron'}
							<div class="detail-list">
								{#if result.cron_jobs.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.cron_jobs as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<code class="detail-path">{item.schedule}</code>
												<span class="detail-owner">👤 {item.user}</span>
											</div>
											<p class="detail-desc"><code>{item.command}</code></p>
											<p class="detail-hint">{item.description}</p>
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'writable'}
							<div class="detail-list">
								{#if result.writable_paths.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.writable_paths as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<code class="detail-path">{item.path}</code>
											</div>
											<div class="detail-meta">
												<span class="detail-perms">📋 {item.permissions}</span>
											</div>
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'services'}
							<div class="detail-list">
								{#if result.vulnerable_services.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.vulnerable_services as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<strong class="detail-name">{item.name}</strong>
												<span class="detail-version">v{item.version}</span>
											</div>
											{#if item.config_path}
												<p class="detail-desc">📁 {item.config_path}</p>
											{/if}
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'kernel'}
							<div class="detail-list">
								{#if result.kernel_exploits.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.kernel_exploits as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<strong class="detail-name">{item.name}</strong>
												<span class="detail-cve">{item.cve}</span>
											</div>
											<p class="detail-desc">🐧 {item.kernel_version}</p>
											<p class="detail-desc">{item.description}</p>
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'docker'}
							<div class="detail-list">
								{#if result.docker_issues.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.docker_issues as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<strong class="detail-name">{item.issue_type}</strong>
											</div>
											<p class="detail-desc">{item.description}</p>
											{#if item.exploit_hint}
												<p class="detail-hint">🎯 {item.exploit_hint}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{:else if activeResultTab === 'misconfig'}
							<div class="detail-list">
								{#if result.misconfigurations.length === 0}
									<div class="empty-detail">{$tr('privilegeEscCheck.noResults')}</div>
								{:else}
									{#each result.misconfigurations as item}
										<div class="detail-card" style="border-left-color: {getSeverityColor(item.risk_level)}">
											<div class="detail-header">
												<span class="detail-severity" style="background: {getSeverityBg(item.risk_level)}; color: {getSeverityColor(item.risk_level)}">{getSeverityLabel(item.risk_level)}</span>
												<strong class="detail-name">{item.category}</strong>
											</div>
											<p class="detail-desc">{item.description}</p>
											{#if item.recommendation}
												<p class="detail-hint">💡 {item.recommendation}</p>
											{/if}
										</div>
									{/each}
								{/if}
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🔓</div>
							<p>{$tr('privilegeEscCheck.emptyState')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="privilege_esc_check" toolName={$tr('privilegeEscCheck.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="privilege_esc_check" />
		</div>
	{/if}
</div>

<style>
	.nd-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}

	.page-header {
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.back-link {
		color: #94a3b8;
		text-decoration: none;
		font-size: 0.8rem;
		transition: color 0.2s;
	}

	.back-link:hover { color: #a855f7; }

	.page-title {
		font-size: 1.5rem;
		font-weight: 700;
		margin: 0.5rem 0 0.25rem;
		color: #f1f5f9;
	}

	.page-subtitle {
		color: #94a3b8;
		font-size: 0.875rem;
		margin: 0;
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1.25rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 0.25rem;
	}

	.tab-btn {
		flex: 1;
		padding: 0.6rem 1rem;
		border: none;
		border-radius: 0.5rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.85rem;
		color: #94a3b8;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
	}

	.tab-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
	}

	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }

	.tab-icon { font-size: 0.9rem; }

	.content-grid {
		display: grid;
		grid-template-columns: 340px 1fr;
		gap: 1.25rem;
	}

	.section-card {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 1.25rem;
	}

	.section-title {
		font-size: 1rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 0.25rem;
	}

	.section-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 1rem;
	}

	.form-group { margin-bottom: 0.75rem; }

	.form-label {
		display: block;
		font-size: 0.75rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.form-input {
		width: 100%;
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.85rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: #a855f7;
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15);
	}

	.form-input::placeholder { color: #475569; }

	.check-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.35rem;
	}

	.check-chip {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.check-chip.active {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.check-chip input[type="checkbox"] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.check-icon { font-size: 0.8rem; }

	.button-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 1rem;
	}

	.btn-primary {
		flex: 1;
		padding: 0.6rem 1rem;
		border-radius: 0.5rem;
		border: none;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		cursor: pointer;
		font-size: 0.85rem;
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
		transition: all 0.2s;
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
	}

	.btn-primary:hover:not(:disabled) {
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

	.btn-secondary {
		padding: 0.6rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.btn-secondary:hover:not(:disabled) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.error-banner {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: rgba(239, 68, 68, 0.08);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 0.5rem;
		color: #f87171;
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.error-icon { font-size: 1.1rem; }

	.score-section { margin-bottom: 0.75rem; }

	.score-row {
		display: flex;
		align-items: center;
		gap: 1.25rem;
	}

	.score-circle {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		border: 4px solid;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.score-number {
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.score-max {
		font-size: 0.6rem;
		color: #64748b;
	}

	.score-details {
		flex: 1;
	}

	.score-level {
		font-size: 1rem;
		font-weight: 600;
		margin-bottom: 0.4rem;
	}

	.score-stats {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-bottom: 0.3rem;
	}

	.stat-item {
		font-size: 0.75rem;
		font-weight: 500;
	}

	.stat-item.critical { color: #f87171; }
	.stat-item.high { color: #fb923c; }
	.stat-item.medium { color: #fbbf24; }
	.stat-item.low { color: #60a5fa; }

	.score-total {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.export-group {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		flex-shrink: 0;
	}

	.export-select {
		padding: 0.4rem 0.6rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(15, 23, 42, 0.8);
		color: #e2e8f0;
		font-size: 0.75rem;
		cursor: pointer;
	}

	.btn-export {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.4rem 0.8rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.1);
		color: #22c55e;
		cursor: pointer;
		font-size: 0.75rem;
		white-space: nowrap;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.2);
		border-color: rgba(34, 197, 94, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.user-section { margin-bottom: 0.75rem; }

	.user-row {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.user-main {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.user-icon { font-size: 1.1rem; }

	.user-name {
		font-size: 0.95rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.user-uid {
		font-size: 0.75rem;
		color: #94a3b8;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.root-badge {
		font-size: 0.65rem;
		padding: 0.1rem 0.4rem;
		background: rgba(239, 68, 68, 0.2);
		color: #f87171;
		border-radius: 0.25rem;
		font-weight: 700;
		letter-spacing: 0.05em;
	}

	.user-meta {
		display: flex;
		gap: 1rem;
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.user-groups {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
	}

	.group-tag {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		background: rgba(168, 85, 247, 0.15);
		color: #c4b5fd;
		border-radius: 0.25rem;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.result-tab {
		padding: 0.4rem 0.65rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.72rem;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.result-tab.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
		box-shadow: 0 2px 6px rgba(168, 85, 247, 0.3);
	}

	.result-tab:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.findings-overview {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.findings-group {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.findings-group-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0;
		padding-bottom: 0.4rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
	}

	.finding-card {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		border-left: 3px solid;
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.3rem;
	}

	.finding-type {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
		font-weight: 600;
	}

	.finding-severity {
		font-size: 0.6rem;
		padding: 0.1rem 0.3rem;
		border-radius: 0.25rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.finding-desc {
		font-size: 0.8rem;
		color: #e2e8f0;
		margin: 0.15rem 0;
	}

	.finding-hint {
		font-size: 0.75rem;
		color: #94a3b8;
		margin: 0.15rem 0;
	}

	.no-findings {
		text-align: center;
		padding: 2rem 1rem;
		color: #22c55e;
	}

	.no-findings-icon { font-size: 2rem; margin-bottom: 0.5rem; }
	.no-findings p { font-size: 0.9rem; margin: 0; }

	.detail-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.detail-card {
		padding: 0.6rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		border-left: 3px solid;
	}

	.detail-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.3rem;
		flex-wrap: wrap;
	}

	.detail-severity {
		font-size: 0.6rem;
		padding: 0.1rem 0.3rem;
		border-radius: 0.25rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.detail-path {
		font-size: 0.8rem;
		color: #a855f7;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.detail-owner {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.detail-name {
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.detail-version {
		font-size: 0.7rem;
		padding: 0.1rem 0.35rem;
		background: rgba(34, 197, 94, 0.15);
		color: #86efac;
		border-radius: 0.25rem;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.detail-cve {
		font-size: 0.7rem;
		padding: 0.1rem 0.35rem;
		background: rgba(239, 68, 68, 0.15);
		color: #f87171;
		border-radius: 0.25rem;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.detail-meta {
		display: flex;
		gap: 0.75rem;
		margin-bottom: 0.2rem;
	}

	.detail-perms {
		font-size: 0.7rem;
		color: #94a3b8;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.detail-desc {
		font-size: 0.8rem;
		color: #e2e8f0;
		margin: 0.15rem 0;
	}

	.detail-hint {
		font-size: 0.75rem;
		color: #94a3b8;
		margin: 0.15rem 0;
	}

	.empty-detail {
		text-align: center;
		padding: 2rem 1rem;
		color: #94a3b8;
		font-size: 0.85rem;
	}

	.empty-state {
		text-align: center;
		padding: 2.5rem 1rem;
		color: #94a3b8;
	}

	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}

		.score-row {
			flex-direction: column;
			align-items: flex-start;
		}

		.result-tabs {
			overflow-x: auto;
			flex-wrap: nowrap;
		}
	}
</style>
