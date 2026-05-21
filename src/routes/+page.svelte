<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { tr } from '$lib/i18n';

	interface DashboardScanStats {
		total_scans: number;
		completed_scans: number;
		failed_scans: number;
		running_scans: number;
		total_open_ports: number;
		success_rate: number;
	}

	interface DashboardTargetStats {
		total_targets: number;
		total_groups: number;
		total_vulnerabilities: number;
		active_targets: number;
		at_risk_targets: number;
	}

	interface DashboardRiskDistribution {
		critical: number;
		high: number;
		medium: number;
		low: number;
		info: number;
	}

	interface DashboardActivityItem {
		tool_type: string;
		tool_name: string;
		input_summary: string;
		status: string;
		created_at: string;
	}

	interface DashboardToolUsage {
		tool_type: string;
		tool_name: string;
		count: number;
	}

	interface SystemInfo {
		cpu_cores: number;
		total_memory_mb: number;
		available_memory_mb: number;
		cpu_usage_percent: number;
		load_average: number;
		optimal_concurrency: number;
		recommended_timeout: number;
		summary: string;
	}

	interface DashboardData {
		scan_stats: DashboardScanStats;
		target_stats: DashboardTargetStats;
		risk_distribution: DashboardRiskDistribution;
		recent_activity: DashboardActivityItem[];
		tool_usage: DashboardToolUsage[];
		system_info: SystemInfo;
	}

	let data: DashboardData | null = null;
	let loading = true;
	let loadError = false;
	let lastUpdated: string = '';
	let refreshing = false;
	let refreshInterval: ReturnType<typeof setInterval> | null = null;
	const AUTO_REFRESH_MS = 30000;

	async function loadDashboardData() {
		try {
			const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;
			if (!isTauri) return;
			const { invoke } = await import('@tauri-apps/api/core');
			const result = await invoke<DashboardData>('get_dashboard_data');
			data = result;
			loadError = false;
			lastUpdated = new Date().toLocaleTimeString();
		} catch (e) {
			console.error('Failed to load dashboard data:', e);
			if (!data) loadError = true;
		}
	}

	async function refreshData() {
		refreshing = true;
		await loadDashboardData();
		refreshing = false;
	}

	onMount(async () => {
		loading = true;
		await loadDashboardData();
		loading = false;
		refreshInterval = setInterval(async () => {
			await loadDashboardData();
		}, AUTO_REFRESH_MS);
	});

	onDestroy(() => {
		if (refreshInterval) {
			clearInterval(refreshInterval);
			refreshInterval = null;
		}
	});

	function navigateTo(path: string) {
		goto(path);
	}

	const quickActions = [
		{ icon: '🔍', labelKey: 'dashboard.quickActionsList.portScan', href: '/tools/port_scanner' },
		{ icon: '🌐', labelKey: 'dashboard.quickActionsList.subdomainEnum', href: '/tools/subdomain_enum' },
		{ icon: '📡', labelKey: 'dashboard.quickActionsList.ping', href: '/tools/ping' },
		{ icon: '🔒', labelKey: 'dashboard.quickActionsList.sslCheck', href: '/tools/ssl_checker' },
		{ icon: '🛡️', labelKey: 'dashboard.quickActionsList.wafDetect', href: '/tools/waf_detector' },
		{ icon: '👤', labelKey: 'dashboard.quickActionsList.usernameOsint', href: '/tools/username_osint' },
		{ icon: '📋', labelKey: 'dashboard.quickActionsList.dnsQuery', href: '/tools/dns_query' },
		{ icon: '🎯', labelKey: 'dashboard.quickActionsList.targetManager', href: '/tools/target_manager' },
		{ icon: '📊', labelKey: 'dashboard.quickActionsList.scanHistory', href: '/history' },
	];

	function statusClass(status: string): string {
		switch (status) {
			case 'completed': return 'status-ok';
			case 'failed': case 'error': return 'status-err';
			case 'running': return 'status-run';
			default: return 'status-warn';
		}
	}

	function statusIcon(status: string): string {
		switch (status) {
			case 'completed': return '✅';
			case 'failed': case 'error': return '❌';
			case 'running': return '🔄';
			default: return '⏳';
		}
	}

	function toolIcon(toolType: string): string {
		const map: Record<string, string> = {
			port_scanner: '🔍', ping: '📡', dns_query: '🌐', ssl_checker: '🔒',
			waf_detector: '🛡️', subdomain_enum: '🔎', dir_scanner: '📂',
			username_osint: '👤', whois: '📋', site_checker: '🏠',
			tech_detector: '⚙️', secret_scanner: '🔑', sqli_scanner: '💉',
			xss_scanner: '⚠️', exploit_framework: '💣', binary_analyzer: '📦',
			apk_analysis: '📱', cloud_audit: '☁️', ad_audit: '🏢',
			web_crawler: '🕷️', security_headers: '📝', cors_checker: '🔗',
			brute_force: '🔨', hash_cracker: '🔐', steganography: '🖼️',
			metadata_extractor: '📎', forensics_analyzer: '🔬',
			network_discovery: '📡', wifi_scanner: '📶', bluetooth_scanner: '📳',
			osint_gather: '🕵️', social_finder: '👥', email_verifier: '📧',
			reverse_ip: '🔄', cf_bypass: '☁️', dns_analyzer: '📊',
			ddos_tester: '🌊', privilege_esc_check: '⬆️', post_exploitation: '🎯',
			payload_injector: '💉', phishing_detector: '🎣', anonymity_checker: '👻',
			mobile_security: '📱', asset_search: '🔎', command_injection: '⌨️',
			open_redirect: '↗️', cookie_analyzer: '🍪', admin_finder: '🔑',
			cve_lookup: '📚', idn_checker: '🌍', reverse_engineer: '🔧',
			rat_tool: '🐀', memory_forensics: '🧠', firmware_analyzer: '💾',
			social_engineering: '🎭', wordlist_generator: '📝',
			param_discovery: '🔍', subdomain_takeover: '🏴', zip: '📦',
			password: '🔑', encoder: '🔤', host_to_ip: '📍', ip_geo: '🗺️',
			hash_identifier: '🔍',
		};
		return map[toolType] || '🔧';
	}

	$: maxRisk = data ? Math.max(data.risk_distribution.critical, data.risk_distribution.high, data.risk_distribution.medium, data.risk_distribution.low, data.risk_distribution.info, 1) : 1;
	$: maxTool = data && data.tool_usage.length > 0 ? Math.max(...data.tool_usage.map(t => t.count), 1) : 1;
	$: memUsed = data ? data.system_info.total_memory_mb - data.system_info.available_memory_mb : 0;
	$: memPercent = data && data.system_info.total_memory_mb > 0 ? (memUsed / data.system_info.total_memory_mb) * 100 : 0;
</script>

<div class="dashboard">
	<div class="dashboard-header">
		<div class="header-left">
			<h1 class="title">{$tr('dashboard.title')}</h1>
			<p class="subtitle">{$tr('dashboard.subtitle')}</p>
		</div>
		<div class="header-right">
			{#if lastUpdated}
				<span class="update-time">{$tr('dashboard.updated')} {lastUpdated}</span>
			{/if}
			<button class="refresh-btn" onclick={refreshData} disabled={refreshing} title={$tr('dashboard.refresh')}>
				<span class="refresh-icon" class:spinning={refreshing}>🔄</span>
			</button>
			{#if data}
				<span class="live-dot"></span>
				<span class="live-text">{$tr('dashboard.live')}</span>
			{/if}
		</div>
	</div>

	{#if loading}
		<div class="loading-state">
			<div class="spinner"></div>
			<p>{$tr('common.loading')}</p>
		</div>
	{:else if loadError && !data}
		<div class="error-state">
			<span class="error-icon">⚠️</span>
			<p>{$tr('dashboard.loadError')}</p>
			<button class="retry-btn" onclick={refreshData}>{$tr('common.retry')}</button>
		</div>
	{:else if data}
		<section class="stats-row">
			<button class="stat-card" onclick={() => navigateTo('/history')}>
				<div class="stat-icon-bg" style="background: rgba(99, 102, 241, 0.15);">
					<span class="stat-icon-text">🔍</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.scan_stats.total_scans}</div>
					<div class="stat-label">{$tr('dashboard.totalScans')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(99, 102, 241, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/history')}>
				<div class="stat-icon-bg" style="background: rgba(16, 185, 129, 0.15);">
					<span class="stat-icon-text">✅</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.scan_stats.completed_scans}</div>
					<div class="stat-label">{$tr('dashboard.completedScans')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(16, 185, 129, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/history')}>
				<div class="stat-icon-bg" style="background: rgba(168, 85, 247, 0.15);">
					<span class="stat-icon-text">📊</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.scan_stats.success_rate.toFixed(1)}%</div>
					<div class="stat-label">{$tr('dashboard.successRate')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(168, 85, 247, 0.3);"></div>
				<svg class="progress-ring" viewBox="0 0 36 36">
					<circle class="ring-bg" cx="18" cy="18" r="15" />
					<circle class="ring-fill" cx="18" cy="18" r="15"
						stroke-dasharray="{data.scan_stats.success_rate * 0.942}, 94.2" />
				</svg>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/history')}>
				<div class="stat-icon-bg" style="background: rgba(245, 158, 11, 0.15);">
					<span class="stat-icon-text">🌐</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.scan_stats.total_open_ports}</div>
					<div class="stat-label">{$tr('dashboard.openPortsFound')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(245, 158, 11, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/tools/target_manager')}>
				<div class="stat-icon-bg" style="background: rgba(59, 130, 246, 0.15);">
					<span class="stat-icon-text">🎯</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.target_stats.total_targets}</div>
					<div class="stat-label">{$tr('dashboard.totalTargets')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(59, 130, 246, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/tools/target_manager')}>
				<div class="stat-icon-bg" style="background: rgba(236, 72, 153, 0.15);">
					<span class="stat-icon-text">📁</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.target_stats.total_groups}</div>
					<div class="stat-label">{$tr('dashboard.totalGroups')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(236, 72, 153, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/tools/target_manager')}>
				<div class="stat-icon-bg" style="background: rgba(239, 68, 68, 0.15);">
					<span class="stat-icon-text">⚠️</span>
				</div>
				<div class="stat-body">
					<div class="stat-value">{data.target_stats.total_vulnerabilities}</div>
					<div class="stat-label">{$tr('dashboard.totalVulnerabilities')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(239, 68, 68, 0.3);"></div>
			</button>

			<button class="stat-card" onclick={() => navigateTo('/tools/target_manager')}>
				<div class="stat-icon-bg" style="background: rgba(239, 68, 68, 0.15);">
					<span class="stat-icon-text">🚨</span>
				</div>
				<div class="stat-body">
					<div class="stat-value" style="color: #ef4444;">{data.target_stats.at_risk_targets}</div>
					<div class="stat-label">{$tr('dashboard.atRiskTargets')}</div>
				</div>
				<div class="stat-glow" style="background: rgba(239, 68, 68, 0.3);"></div>
			</button>
		</section>

		<section class="scan-status-row">
			<div class="panel scan-status-panel">
				<h2 class="panel-title">📈 {$tr('dashboard.scanStatus')}</h2>
				<div class="scan-status-content">
					<div class="donut-container">
						<svg class="donut" viewBox="0 0 120 120">
							<circle class="donut-bg" cx="60" cy="60" r="48" />
							{#if data.scan_stats.completed_scans + data.scan_stats.failed_scans + data.scan_stats.running_scans > 0}
								{@const totalStatus = data.scan_stats.completed_scans + data.scan_stats.failed_scans + data.scan_stats.running_scans}
								{@const circumference = 2 * Math.PI * 48}
								{@const completedDash = (data.scan_stats.completed_scans / totalStatus) * circumference}
								{@const failedDash = (data.scan_stats.failed_scans / totalStatus) * circumference}
								{@const runningDash = (data.scan_stats.running_scans / totalStatus) * circumference}
								<circle class="donut-segment completed" cx="60" cy="60" r="48"
									stroke-dasharray="{completedDash} {circumference - completedDash}"
									stroke-dashoffset="-{circumference * 0.25}" />
								<circle class="donut-segment failed" cx="60" cy="60" r="48"
									stroke-dasharray="{failedDash} {circumference - failedDash}"
									stroke-dashoffset="-{circumference * 0.25 + completedDash}" />
								<circle class="donut-segment running" cx="60" cy="60" r="48"
									stroke-dasharray="{runningDash} {circumference - runningDash}"
									stroke-dashoffset="-{circumference * 0.25 + completedDash + failedDash}" />
							{/if}
							<text class="donut-center" x="60" y="56" text-anchor="middle">{data.scan_stats.completed_scans + data.scan_stats.failed_scans + data.scan_stats.running_scans}</text>
							<text class="donut-center-label" x="60" y="72" text-anchor="middle">{$tr('dashboard.totalScans')}</text>
						</svg>
					</div>
					<div class="scan-legend">
						<div class="legend-item">
							<span class="legend-dot" style="background: #10b981;"></span>
							<span class="legend-label">{$tr('dashboard.completedScans')}</span>
							<span class="legend-value">{data.scan_stats.completed_scans}</span>
						</div>
						<div class="legend-item">
							<span class="legend-dot" style="background: #ef4444;"></span>
							<span class="legend-label">{$tr('dashboard.failedScans')}</span>
							<span class="legend-value">{data.scan_stats.failed_scans}</span>
						</div>
						<div class="legend-item">
							<span class="legend-dot" style="background: #3b82f6;"></span>
							<span class="legend-label">{$tr('dashboard.runningScans')}</span>
							<span class="legend-value">{data.scan_stats.running_scans}</span>
						</div>
					</div>
				</div>
			</div>
		</section>

		<div class="middle-row">
			<section class="panel risk-panel">
				<h2 class="panel-title">🎯 {$tr('dashboard.riskOverview')}</h2>
				<div class="risk-grid">
					<div class="risk-item critical">
						<div class="risk-bar-track">
							<div class="risk-bar-fill" style="width: {(data.risk_distribution.critical / maxRisk) * 100}%; background: #ef4444;"></div>
						</div>
						<div class="risk-info">
							<span class="risk-label">{$tr('dashboard.riskLevels.critical')}</span>
							<span class="risk-count">{data.risk_distribution.critical}</span>
						</div>
					</div>
					<div class="risk-item high">
						<div class="risk-bar-track">
							<div class="risk-bar-fill" style="width: {(data.risk_distribution.high / maxRisk) * 100}%; background: #f97316;"></div>
						</div>
						<div class="risk-info">
							<span class="risk-label">{$tr('dashboard.riskLevels.high')}</span>
							<span class="risk-count">{data.risk_distribution.high}</span>
						</div>
					</div>
					<div class="risk-item medium">
						<div class="risk-bar-track">
							<div class="risk-bar-fill" style="width: {(data.risk_distribution.medium / maxRisk) * 100}%; background: #eab308;"></div>
						</div>
						<div class="risk-info">
							<span class="risk-label">{$tr('dashboard.riskLevels.medium')}</span>
							<span class="risk-count">{data.risk_distribution.medium}</span>
						</div>
					</div>
					<div class="risk-item low">
						<div class="risk-bar-track">
							<div class="risk-bar-fill" style="width: {(data.risk_distribution.low / maxRisk) * 100}%; background: #22c55e;"></div>
						</div>
						<div class="risk-info">
							<span class="risk-label">{$tr('dashboard.riskLevels.low')}</span>
							<span class="risk-count">{data.risk_distribution.low}</span>
						</div>
					</div>
					<div class="risk-item info">
						<div class="risk-bar-track">
							<div class="risk-bar-fill" style="width: {(data.risk_distribution.info / maxRisk) * 100}%; background: #64748b;"></div>
						</div>
						<div class="risk-info">
							<span class="risk-label">{$tr('dashboard.riskLevels.info')}</span>
							<span class="risk-count">{data.risk_distribution.info}</span>
						</div>
					</div>
				</div>
			</section>

			<section class="panel activity-panel">
				<h2 class="panel-title">📜 {$tr('dashboard.recentActivity')}</h2>
				{#if data.recent_activity.length > 0}
					<div class="timeline">
						{#each data.recent_activity as item}
							<div class="timeline-item">
								<div class="timeline-dot {statusClass(item.status)}"></div>
								<div class="timeline-content">
									<div class="timeline-header">
										<span class="timeline-tool">{toolIcon(item.tool_type)} {item.tool_name}</span>
										<span class="timeline-status">{statusIcon(item.status)}</span>
									</div>
									<div class="timeline-input">{item.input_summary}</div>
									<div class="timeline-time">{item.created_at}</div>
								</div>
							</div>
						{/each}
					</div>
				{:else}
					<div class="empty-state">{$tr('dashboard.noActivity')}</div>
				{/if}
			</section>
		</div>

		<div class="bottom-row">
			<section class="panel actions-panel">
				<h2 class="panel-title">⚡ {$tr('dashboard.quickActions')}</h2>
				<div class="quick-actions">
					{#each quickActions as action}
						<a href={action.href} class="action-card">
							<span class="action-icon">{action.icon}</span>
							<span class="action-label">{$tr(action.labelKey)}</span>
						</a>
					{/each}
				</div>
			</section>

			<section class="panel system-panel">
				<h2 class="panel-title">🖥️ {$tr('dashboard.systemResources')}</h2>
				<div class="resource-bars">
					<div class="resource-item">
						<div class="resource-header">
							<span class="resource-label">{$tr('dashboard.cpuUsage')}</span>
							<span class="resource-value">{data.system_info.cpu_usage_percent.toFixed(1)}%</span>
						</div>
						<div class="resource-track">
							<div class="resource-fill cpu" style="width: {Math.min(data.system_info.cpu_usage_percent, 100)}%;"></div>
						</div>
					</div>
					<div class="resource-item">
						<div class="resource-header">
							<span class="resource-label">{$tr('dashboard.memoryUsage')}</span>
							<span class="resource-value">{memPercent.toFixed(1)}%</span>
						</div>
						<div class="resource-track">
							<div class="resource-fill mem" style="width: {Math.min(memPercent, 100)}%;"></div>
						</div>
					</div>
					<div class="resource-item">
						<div class="resource-header">
							<span class="resource-label">{$tr('dashboard.systemLoad')}</span>
							<span class="resource-value">{data.system_info.load_average.toFixed(1)}</span>
						</div>
						<div class="resource-track">
							<div class="resource-fill load" style="width: {Math.min((data.system_info.load_average / data.system_info.cpu_cores) * 100, 100)}%;"></div>
						</div>
					</div>
				</div>
				<div class="sys-info-grid">
					<div class="sys-info-item">
						<span class="sys-label">{$tr('dashboard.cpuCores')}</span>
						<span class="sys-value">{data.system_info.cpu_cores}</span>
					</div>
					<div class="sys-info-item">
						<span class="sys-label">{$tr('dashboard.availableMemory')}</span>
						<span class="sys-value">{(data.system_info.available_memory_mb / 1024).toFixed(1)} GB</span>
					</div>
					<div class="sys-info-item">
						<span class="sys-label">{$tr('dashboard.recommendedConcurrency')}</span>
						<span class="sys-value">{data.system_info.optimal_concurrency}</span>
					</div>
					<div class="sys-info-item">
						<span class="sys-label">{$tr('dashboard.recommendedTimeout')}</span>
						<span class="sys-value">{data.system_info.recommended_timeout}ms</span>
					</div>
				</div>
			</section>

			<section class="panel tools-panel">
				<h2 class="panel-title">🔧 {$tr('dashboard.toolUsage')}</h2>
				{#if data.tool_usage.length > 0}
					<div class="tool-chart">
						{#each data.tool_usage as tool}
							<div class="tool-bar-item">
								<div class="tool-bar-header">
									<span class="tool-bar-name">{toolIcon(tool.tool_type)} {tool.tool_name}</span>
									<span class="tool-bar-count">{tool.count}</span>
								</div>
								<div class="tool-bar-track">
									<div class="tool-bar-fill" style="width: {(tool.count / maxTool) * 100}%;"></div>
								</div>
							</div>
						{/each}
					</div>
				{:else}
					<div class="empty-state">{$tr('dashboard.noToolUsage')}</div>
				{/if}
			</section>
		</div>
	{:else}
		<div class="empty-state">{$tr('dashboard.noData')}</div>
	{/if}
</div>

<style>
	.dashboard {
		max-width: 1500px;
		margin: 0 auto;
		padding: 0.5rem;
	}

	.dashboard-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.title {
		font-size: 1.75rem;
		font-weight: 700;
		background: linear-gradient(135deg, #a855f7, #6366f1, #3b82f6);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
		margin-bottom: 0.25rem;
	}

	.subtitle {
		color: #64748b;
		font-size: 0.85rem;
	}

	.header-right {
		display: flex;
		align-items: center;
		gap: 0.6rem;
	}

	.update-time {
		font-size: 0.65rem;
		color: #64748b;
	}

	.refresh-btn {
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.4rem;
		padding: 0.3rem 0.5rem;
		cursor: pointer;
		transition: all 0.2s ease;
		display: flex;
		align-items: center;
	}

	.refresh-btn:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.4);
	}

	.refresh-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.refresh-icon {
		font-size: 0.85rem;
		display: inline-block;
		transition: transform 0.3s ease;
	}

	.refresh-icon.spinning {
		animation: spin 0.8s linear infinite;
	}

	.live-badge {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.3rem 0.6rem;
		background: rgba(16, 185, 129, 0.08);
		border: 1px solid rgba(16, 185, 129, 0.2);
		border-radius: 0.5rem;
	}

	.live-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: #10b981;
		animation: pulse 2s infinite;
	}

	.live-text {
		font-size: 0.75rem;
		color: #10b981;
		font-weight: 600;
	}

	@keyframes pulse {
		0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
		50% { opacity: 0.6; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
	}

	.loading-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 6rem;
		color: #64748b;
		gap: 1rem;
	}

	.spinner {
		width: 2.5rem;
		height: 2.5rem;
		border: 3px solid rgba(168, 85, 247, 0.15);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.error-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 4rem;
		color: #94a3b8;
		gap: 0.75rem;
	}

	.error-icon {
		font-size: 2.5rem;
	}

	.retry-btn {
		margin-top: 0.5rem;
		padding: 0.5rem 1.5rem;
		background: rgba(168, 85, 247, 0.15);
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.5rem;
		color: #a855f7;
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s ease;
	}

	.retry-btn:hover {
		background: rgba(168, 85, 247, 0.25);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.empty-state {
		text-align: center;
		padding: 3rem;
		color: #64748b;
		font-size: 0.9rem;
	}

	.stats-row {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.stat-card {
		position: relative;
		background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.9) 100%);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.75rem;
		padding: 1rem 1.25rem;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		overflow: hidden;
		transition: all 0.3s ease;
		cursor: pointer;
		width: 100%;
		text-align: left;
		font-family: inherit;
		color: inherit;
	}

	.stat-card:hover {
		border-color: rgba(168, 85, 247, 0.3);
		transform: translateY(-2px);
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
	}

	.stat-glow {
		position: absolute;
		top: -50%;
		right: -20%;
		width: 120px;
		height: 120px;
		border-radius: 50%;
		filter: blur(40px);
		opacity: 0.15;
		pointer-events: none;
	}

	.stat-icon-bg {
		width: 44px;
		height: 44px;
		border-radius: 0.6rem;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.stat-icon-text {
		font-size: 1.2rem;
	}

	.stat-body {
		flex: 1;
		min-width: 0;
	}

	.stat-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #f1f5f9;
		line-height: 1.2;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin-top: 0.15rem;
	}

	.progress-ring {
		width: 40px;
		height: 40px;
		flex-shrink: 0;
	}

	.ring-bg {
		fill: none;
		stroke: rgba(148, 163, 184, 0.1);
		stroke-width: 2.5;
	}

	.ring-fill {
		fill: none;
		stroke: #a855f7;
		stroke-width: 2.5;
		stroke-linecap: round;
		transform: rotate(-90deg);
		transform-origin: center;
		transition: stroke-dasharray 0.8s ease;
	}

	.scan-status-row {
		margin-bottom: 0.75rem;
	}

	.scan-status-panel {
		display: flex;
		flex-direction: column;
	}

	.scan-status-content {
		display: flex;
		align-items: center;
		gap: 2rem;
		justify-content: center;
		padding: 0.5rem 0;
	}

	.donut-container {
		flex-shrink: 0;
	}

	.donut {
		width: 120px;
		height: 120px;
	}

	.donut-bg {
		fill: none;
		stroke: rgba(148, 163, 184, 0.1);
		stroke-width: 10;
	}

	.donut-segment {
		fill: none;
		stroke-width: 10;
		stroke-linecap: butt;
		transition: stroke-dasharray 0.8s ease, stroke-dashoffset 0.8s ease;
	}

	.donut-segment.completed { stroke: #10b981; }
	.donut-segment.failed { stroke: #ef4444; }
	.donut-segment.running { stroke: #3b82f6; }

	.donut-center {
		font-size: 1.2rem;
		font-weight: 700;
		fill: #f1f5f9;
	}

	.donut-center-label {
		font-size: 0.55rem;
		fill: #64748b;
	}

	.scan-legend {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.legend-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		flex-shrink: 0;
	}

	.legend-label {
		font-size: 0.75rem;
		color: #94a3b8;
		flex: 1;
	}

	.legend-value {
		font-size: 0.85rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.middle-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}

	.bottom-row {
		display: grid;
		grid-template-columns: 1fr 1fr 1fr;
		gap: 0.75rem;
	}

	.panel {
		background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.9) 100%);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.75rem;
		padding: 1rem 1.25rem;
	}

	.panel-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #e2e8f0;
		margin-bottom: 0.75rem;
		padding-bottom: 0.5rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.08);
	}

	.risk-grid {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.risk-item {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.risk-bar-track {
		height: 8px;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 4px;
		overflow: hidden;
	}

	.risk-bar-fill {
		height: 100%;
		border-radius: 4px;
		transition: width 0.8s ease;
	}

	.risk-info {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.risk-label {
		font-size: 0.75rem;
		color: #94a3b8;
	}

	.risk-count {
		font-size: 0.85rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.timeline {
		display: flex;
		flex-direction: column;
		gap: 0;
		max-height: 280px;
		overflow-y: auto;
	}

	.timeline-item {
		display: flex;
		gap: 0.6rem;
		padding: 0.45rem 0;
		border-bottom: 1px solid rgba(148, 163, 184, 0.05);
	}

	.timeline-item:last-child { border-bottom: none; }

	.timeline-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		margin-top: 0.25rem;
		flex-shrink: 0;
	}

	.timeline-dot.status-ok { background: #10b981; box-shadow: 0 0 6px rgba(16, 185, 129, 0.4); }
	.timeline-dot.status-err { background: #ef4444; box-shadow: 0 0 6px rgba(239, 68, 68, 0.4); }
	.timeline-dot.status-run { background: #3b82f6; box-shadow: 0 0 6px rgba(59, 130, 246, 0.4); animation: pulse 1.5s infinite; }
	.timeline-dot.status-warn { background: #f59e0b; box-shadow: 0 0 6px rgba(245, 158, 11, 0.4); }

	.timeline-content {
		flex: 1;
		min-width: 0;
	}

	.timeline-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.15rem;
	}

	.timeline-tool {
		font-size: 0.78rem;
		font-weight: 600;
		color: #e2e8f0;
	}

	.timeline-status {
		font-size: 0.7rem;
	}

	.timeline-input {
		font-size: 0.7rem;
		color: #94a3b8;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.timeline-time {
		font-size: 0.65rem;
		color: #64748b;
		margin-top: 0.1rem;
	}

	.quick-actions {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.5rem;
	}

	.action-card {
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		padding: 0.6rem 0.5rem;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.35rem;
		cursor: pointer;
		transition: all 0.25s ease;
		text-decoration: none;
	}

	.action-card:hover {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.08);
		transform: translateY(-2px);
		box-shadow: 0 4px 16px rgba(168, 85, 247, 0.15);
	}

	.action-icon {
		font-size: 1.3rem;
	}

	.action-label {
		font-size: 0.7rem;
		font-weight: 500;
		color: #cbd5e1;
		text-align: center;
		line-height: 1.2;
	}

	.resource-bars {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		margin-bottom: 0.75rem;
	}

	.resource-item {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.resource-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.resource-label {
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.resource-value {
		font-size: 0.75rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.resource-track {
		height: 6px;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 3px;
		overflow: hidden;
	}

	.resource-fill {
		height: 100%;
		border-radius: 3px;
		transition: width 0.6s ease;
	}

	.resource-fill.cpu { background: linear-gradient(90deg, #6366f1, #a855f7); }
	.resource-fill.mem { background: linear-gradient(90deg, #ec4899, #f97316); }
	.resource-fill.load { background: linear-gradient(90deg, #3b82f6, #06b6d4); }

	.sys-info-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.4rem;
	}

	.sys-info-item {
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
		padding: 0.35rem 0.5rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.35rem;
	}

	.sys-label {
		font-size: 0.6rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.03em;
	}

	.sys-value {
		font-size: 0.8rem;
		font-weight: 700;
		color: #e2e8f0;
	}

	.tool-chart {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.tool-bar-item {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.tool-bar-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.tool-bar-name {
		font-size: 0.72rem;
		color: #cbd5e1;
		font-weight: 500;
	}

	.tool-bar-count {
		font-size: 0.7rem;
		font-weight: 700;
		color: #a855f7;
	}

	.tool-bar-track {
		height: 6px;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 3px;
		overflow: hidden;
	}

	.tool-bar-fill {
		height: 100%;
		border-radius: 3px;
		background: linear-gradient(90deg, #a855f7, #6366f1);
		transition: width 0.6s ease;
	}

	@media (max-width: 1200px) {
		.stats-row { grid-template-columns: repeat(4, 1fr); }
		.bottom-row { grid-template-columns: 1fr 1fr; }
	}

	@media (max-width: 900px) {
		.stats-row { grid-template-columns: repeat(2, 1fr); }
		.middle-row { grid-template-columns: 1fr; }
		.bottom-row { grid-template-columns: 1fr; }
		.quick-actions { grid-template-columns: repeat(3, 1fr); }
	}

	@media (max-width: 500px) {
		.stats-row { grid-template-columns: 1fr 1fr; }
		.quick-actions { grid-template-columns: repeat(2, 1fr); }
	}
</style>
