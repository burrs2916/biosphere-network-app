<script lang="ts">
	import { tr } from '$lib/i18n';

	interface DiscoveredPort {
		port: number;
		protocol: string;
		state: string;
		service: string;
		version: string | null;
	}

	interface DetectedService {
		name: string;
		port: number;
		version: string | null;
		banner: string | null;
	}

	interface DiscoveredHost {
		ip: string;
		hostname: string | null;
		mac_address: string | null;
		vendor: string | null;
		os_guess: string | null;
		ports: DiscoveredPort[];
		response_time_ms: number;
		risk_level: string;
		services: DetectedService[];
	}

	interface TopologyNode {
		id: string;
		label: string;
		node_type: string;
		ip: string | null;
		icon: string;
		risk_level: string | null;
	}

	interface TopologyEdge {
		source: string;
		target: string;
		edge_type: string;
		label: string | null;
	}

	interface NetworkTopology {
		gateway: string | null;
		subnet_mask: string | null;
		dns_servers: string[];
		dhcp_server: string | null;
		network_type: string;
		nodes: TopologyNode[];
		edges: TopologyEdge[];
	}

	interface NetworkSecurityFinding {
		severity: string;
		category: string;
		description: string;
		affected_host: string;
		recommendation: string;
	}

	interface NetworkDiscoveryResult {
		success: boolean;
		network_range: string;
		hosts: DiscoveredHost[];
		network_topology: NetworkTopology;
		security_findings: NetworkSecurityFinding[];
		total_scanned: number;
		active_hosts: number;
		summary: string;
	}

	interface HistoryRecord {
		id: number;
		network_range: string;
		active_hosts: number;
		total_scanned: number;
		summary: string;
		result: string;
		created_at: string;
	}

	let networkRange = '192.168.1.0/24';
	let timeout = 2;
	let concurrentLimit = 50;
	let scanType = 'tcp';
	let detectOs = true;
	let detectServices = true;
	let result: NetworkDiscoveryResult | null = null;
	let error = '';
	let processing = false;
	let activeTab = 'scan';
	let showHelpModal = false;
	let selectedHost: DiscoveredHost | null = null;
	let showHostDetail = false;

	let history: HistoryRecord[] = [];
	let loadingHistory = false;
	let historyError = '';
	let historyCurrentPage = 1;
	let historyPageSize = 20;
	let selectedHistoryItem: any | null = null;
	let showHistoryDetail = false;

	let topologyLayout: { x: number; y: number; node: TopologyNode }[] = [];

	const riskColorMap: Record<string, string> = {
		high: '#ef4444',
		medium: '#f59e0b',
		low: '#22c55e',
		info: '#3b82f6',
		unknown: '#6b7280'
	};

	function computeTopologyLayout(nodes: TopologyNode[], edges: TopologyEdge[]) {
		if (nodes.length === 0) { topologyLayout = []; return; }

		const internetNode = nodes.find(n => n.node_type === 'internet');
		const gatewayNode = nodes.find(n => n.node_type === 'gateway');
		const dnsNodes = nodes.filter(n => n.node_type === 'dns');
		const otherNodes = nodes.filter(n => n.node_type !== 'internet' && n.node_type !== 'gateway' && n.node_type !== 'dns');

		const layout: { x: number; y: number; node: TopologyNode }[] = [];
		const centerX = 400;
		const startY = 50;

		if (internetNode) {
			layout.push({ x: centerX, y: startY, node: internetNode });
		}
		if (gatewayNode) {
			layout.push({ x: centerX, y: startY + 120, node: gatewayNode });
		}

		if (dnsNodes.length > 0) {
			const dnsSpacing = 160;
			const dnsStartX = centerX - (dnsNodes.length - 1) * dnsSpacing / 2;
			dnsNodes.forEach((dns, i) => {
				layout.push({ x: dnsStartX + i * dnsSpacing, y: startY + 240, node: dns });
			});
		}

		if (otherNodes.length > 0) {
			const cols = Math.min(otherNodes.length, 5);
			const rows = Math.ceil(otherNodes.length / cols);
			const spacingX = 160;
			const spacingY = 110;
			const startX = centerX - (cols - 1) * spacingX / 2;
			const baseY = startY + 360;

			otherNodes.forEach((node, i) => {
				const row = Math.floor(i / cols);
				const col = i % cols;
				const rowCount = row === rows - 1 ? otherNodes.length - row * cols : cols;
				const rowStartX = centerX - (rowCount - 1) * spacingX / 2;
				layout.push({ x: rowStartX + col * spacingX, y: baseY + row * spacingY, node });
			});
		}

		topologyLayout = layout;
	}

	async function discover() {
		if (!networkRange.trim()) { error = $tr('networkDiscovery.errors.rangeRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<NetworkDiscoveryResult>('discover_network_command', {
				config: {
					network_range: networkRange.trim(),
					timeout,
					concurrent_limit: concurrentLimit,
					scan_type: scanType,
					ports: [22, 80, 443, 3389, 8080, 8443, 21, 25, 53, 110, 139, 445, 3306, 5432, 6379, 27017],
					detect_os: detectOs,
					detect_services: detectServices,
					deep_scan: false,
				}
			});
			if (result) {
				computeTopologyLayout(result.network_topology.nodes, result.network_topology.edges);
				await invoke('save_network_discovery_record', {
					networkRange: result.network_range,
					activeHosts: result.active_hosts,
					totalScanned: result.total_scanned,
					summary: result.summary,
					result: JSON.stringify(result),
				});
			}
		} catch (e: any) {
			error = e.toString();
		} finally { processing = false; }
	}

	function clearAll() {
		networkRange = '192.168.1.0/24';
		result = null; error = ''; topologyLayout = [];
	}

	async function loadHistory() {
		loadingHistory = true; historyError = '';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			history = await invoke<HistoryRecord[]>('get_network_discovery_history', {
				limit: historyPageSize,
				offset: (historyCurrentPage - 1) * historyPageSize,
			});
		} catch (e: any) {
			historyError = `${$tr('networkDiscovery.history.messages.loadFailed')}: ${e}`;
		} finally { loadingHistory = false; }
	}

	async function deleteHistoryItem(id: number) {
		if (!confirm($tr('networkDiscovery.history.messages.deleteConfirmMessage'))) return;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('delete_network_discovery_record', { id });
			await loadHistory();
		} catch (e: any) {
			historyError = `${$tr('networkDiscovery.history.messages.deleteFailed')}: ${e}`;
		}
	}

	async function clearAllHistory() {
		if (!confirm($tr('networkDiscovery.history.messages.clearAllConfirmMessage'))) return;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('clear_network_discovery_history');
			await loadHistory();
		} catch (e: any) {
			historyError = `${$tr('networkDiscovery.history.messages.clearFailed')}: ${e}`;
		}
	}

	function viewHistoryDetail(item: HistoryRecord) {
		try {
			const parsed = JSON.parse(item.result);
			selectedHistoryItem = { ...parsed, _id: item.id, _created_at: item.created_at };
			showHistoryDetail = true;
		} catch {
			selectedHistoryItem = null;
		}
	}

	function rescanFromHistory(item: HistoryRecord) {
		networkRange = item.network_range;
		activeTab = 'scan';
		discover();
	}

	function rescanFromDetail(item: any) {
		if (item.network_range) {
			networkRange = item.network_range;
		}
		showHistoryDetail = false;
		activeTab = 'scan';
		discover();
	}

	function showHostInfo(host: DiscoveredHost) {
		selectedHost = host;
		showHostDetail = true;
	}

	function getRiskBadgeClass(risk: string): string {
		switch (risk) {
			case 'high': return 'risk-high';
			case 'medium': return 'risk-medium';
			case 'low': return 'risk-low';
			default: return 'risk-unknown';
		}
	}

	function getRiskLabel(risk: string): string {
		switch (risk) {
			case 'high': return $tr('networkDiscovery.result.riskHigh');
			case 'medium': return $tr('networkDiscovery.result.riskMedium');
			case 'low': return $tr('networkDiscovery.result.riskLow');
			default: return $tr('networkDiscovery.result.riskUnknown');
		}
	}

	function getSeverityClass(severity: string): string {
		switch (severity) {
			case 'high': return 'severity-high';
			case 'medium': return 'severity-medium';
			case 'low': return 'severity-low';
			default: return 'severity-info';
		}
	}

	function getNodePosition(nodeId: string): { x: number; y: number } | null {
		const found = topologyLayout.find(l => l.node.id === nodeId);
		return found ? { x: found.x, y: found.y } : null;
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">{$tr('networkDiscovery.title')}</h1>
			<p class="page-subtitle">{$tr('networkDiscovery.subtitle')}</p>
		</div>
		<div class="header-actions">
			<button class="help-button" on:click={() => showHelpModal = true}>?</button>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-button {activeTab === 'scan' ? 'active' : ''}" on:click={() => activeTab = 'scan'}>
			{$tr('networkDiscovery.tabs.scan')}
		</button>
		<button class="tab-button {activeTab === 'topology' ? 'active' : ''}" on:click={() => activeTab = 'topology'} disabled={!result}>
			{$tr('networkDiscovery.tabs.topology')}
		</button>
		<button class="tab-button {activeTab === 'hosts' ? 'active' : ''}" on:click={() => activeTab = 'hosts'} disabled={!result}>
			{$tr('networkDiscovery.tabs.hosts')}
		</button>
		<button class="tab-button {activeTab === 'security' ? 'active' : ''}" on:click={() => activeTab = 'security'} disabled={!result || (result?.security_findings.length ?? 0) === 0}>
			{$tr('networkDiscovery.tabs.security')}
		</button>
		<button class="tab-button {activeTab === 'history' ? 'active' : ''}" on:click={() => { activeTab = 'history'; loadHistory(); }}>
			{$tr('networkDiscovery.tabs.history')}
		</button>
	</div>

	{#if activeTab === 'scan'}
		<div class="content-grid">
			<div class="config-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('networkDiscovery.scanConfig')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('networkDiscovery.networkRange')}</label>
						<input type="text" bind:value={networkRange} placeholder="192.168.1.0/24" class="form-input" disabled={processing} />
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('networkDiscovery.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="1" max="10" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('networkDiscovery.concurrent')}</label>
							<input type="number" bind:value={concurrentLimit} class="form-input" min="10" max="200" disabled={processing} />
						</div>
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('networkDiscovery.scanType')}</label>
							<select bind:value={scanType} class="form-input" disabled={processing}>
								<option value="tcp">TCP</option>
								<option value="syn">SYN</option>
								<option value="udp">UDP</option>
							</select>
						</div>
						<div class="form-group">
							<div class="checkbox-group">
								<label class="checkbox-label">
									<input type="checkbox" bind:checked={detectOs} disabled={processing} />
									{$tr('networkDiscovery.detectOs')}
								</label>
								<label class="checkbox-label">
									<input type="checkbox" bind:checked={detectServices} disabled={processing} />
									{$tr('networkDiscovery.detectServices')}
								</label>
							</div>
						</div>
					</div>
					<div class="button-group">
						<button class="btn-primary" on:click={discover} disabled={processing || !networkRange.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('networkDiscovery.scanning')}{:else}{$tr('networkDiscovery.startScan')}{/if}
						</button>
						<button class="btn-secondary" on:click={clearAll} disabled={processing}>{$tr('common.reset')}</button>
					</div>
				</div>
			</div>
			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('networkDiscovery.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-message">{error}</div>
						</div>
					{:else if result}
						<div class="result-summary">{result.summary}</div>
						<div class="scan-stats">
							<span class="stat-badge">{$tr('networkDiscovery.result.scanned')}: {result.total_scanned}</span>
							<span class="stat-badge stat-active">{$tr('networkDiscovery.result.active')}: {result.active_hosts}</span>
							<span class="stat-badge stat-finding">{$tr('networkDiscovery.result.findings')}: {result.security_findings.length}</span>
						</div>
						{#if result.network_topology.gateway}
							<div class="topology-info">
								<div class="info-item"><span class="info-label">{$tr('networkDiscovery.result.gateway')}</span><span class="info-value">{result.network_topology.gateway}</span></div>
								<div class="info-item"><span class="info-label">{$tr('networkDiscovery.result.subnet')}</span><span class="info-value">{result.network_topology.subnet_mask || '-'}</span></div>
								<div class="info-item"><span class="info-label">{$tr('networkDiscovery.result.dns')}</span><span class="info-value">{result.network_topology.dns_servers.join(', ')}</span></div>
								<div class="info-item"><span class="info-label">{$tr('networkDiscovery.result.dhcp')}</span><span class="info-value">{result.network_topology.dhcp_server || '-'}</span></div>
							</div>
						{/if}
						{#if result.hosts.length > 0}
							<div class="mini-topology-preview">
								<h4>{$tr('networkDiscovery.result.topologyPreview')}</h4>
								<svg viewBox="0 0 800 200" class="topology-svg-mini">
									{#each result.network_topology.edges as edge}
										{@const sourcePos = getNodePosition(edge.source)}
										{@const targetPos = getNodePosition(edge.target)}
										{#if sourcePos && targetPos}
											<line x1={sourcePos.x} y1={Math.min(sourcePos.y, 80)} x2={targetPos.x} y2={Math.min(targetPos.y, 80)} stroke="#4b5563" stroke-width="1.5" stroke-dasharray={edge.edge_type === 'dns' ? '4,4' : ''} />
										{/if}
									{/each}
									{#each topologyLayout.slice(0, 8) as item}
										<g transform="translate({item.x}, {Math.min(item.y, 80)})">
											<circle r="16" fill={item.node.node_type === 'gateway' ? '#6366f1' : item.node.node_type === 'internet' ? '#3b82f6' : item.node.node_type === 'dns' ? '#8b5cf6' : '#a855f7'} opacity="0.8" />
											<text text-anchor="middle" dy="4" fill="white" font-size="12">{item.node.icon}</text>
											<text text-anchor="middle" dy="30" fill="#94a3b8" font-size="9">{item.node.label.length > 12 ? item.node.label.slice(0, 12) + '...' : item.node.label}</text>
										</g>
									{/each}
								</svg>
								<button class="btn-view-topology" on:click={() => activeTab = 'topology'}>{$tr('networkDiscovery.result.viewTopology')}</button>
							</div>
						{/if}
					{:else}
						<div class="empty-state"><div class="empty-icon">🌐</div><p>{$tr('networkDiscovery.result.noResults')}</p></div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeTab === 'topology'}
		<div class="section-card">
			<h2 class="section-title">{$tr('networkDiscovery.topology.title')}</h2>
			{#if result && topologyLayout.length > 0}
				<div class="topology-legend">
					<span class="legend-item"><span class="legend-dot" style="background: #3b82f6;"></span>{$tr('networkDiscovery.topology.internet')}</span>
					<span class="legend-item"><span class="legend-dot" style="background: #6366f1;"></span>{$tr('networkDiscovery.topology.gateway')}</span>
					<span class="legend-item"><span class="legend-dot" style="background: #8b5cf6;"></span>DNS</span>
					<span class="legend-item"><span class="legend-dot" style="background: #a855f7;"></span>{$tr('networkDiscovery.topology.host')}</span>
					<span class="legend-item"><span class="legend-line"></span>{$tr('networkDiscovery.topology.lanConnection')}</span>
					<span class="legend-item"><span class="legend-line dashed"></span>{$tr('networkDiscovery.topology.dnsConnection')}</span>
				</div>
				<div class="topology-container">
					<svg viewBox="0 0 800 {Math.max(500, topologyLayout.length > 5 ? 600 : 400)}" class="topology-svg">
						<defs>
							<marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
								<polygon points="0 0, 8 3, 0 6" fill="#6b7280" />
							</marker>
							<filter id="glow">
								<feGaussianBlur stdDeviation="3" result="coloredBlur"/>
								<feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
							</filter>
						</defs>
						{#each result.network_topology.edges as edge}
							{@const sourcePos = getNodePosition(edge.source)}
							{@const targetPos = getNodePosition(edge.target)}
							{#if sourcePos && targetPos}
								{@const isWan = edge.edge_type === 'wan'}
								{@const isDns = edge.edge_type === 'dns'}
								<line
									x1={sourcePos.x} y1={sourcePos.y}
									x2={targetPos.x} y2={targetPos.y}
									stroke={isWan ? '#3b82f6' : isDns ? '#8b5cf6' : '#4b5563'}
									stroke-width={isWan ? 3 : 1.5}
									stroke-dasharray={isDns ? '6,4' : ''}
									marker-end={isWan ? 'url(#arrowhead)' : ''}
									opacity="0.7"
								/>
								{#if edge.label}
									<text
										x={(sourcePos.x + targetPos.x) / 2}
										y={(sourcePos.y + targetPos.y) / 2 - 8}
										text-anchor="middle"
										fill="#9ca3af"
										font-size="10"
									>{edge.label}</text>
								{/if}
							{/if}
						{/each}
						{#each topologyLayout as item}
							<g transform="translate({item.x}, {item.y})" class="topology-node" on:click={() => {
								if (item.node.ip && result) {
									const host = result.hosts.find(h => h.ip === item.node.ip);
									if (host) showHostInfo(host);
								}
							}}>
								<circle
									r="24"
									fill={item.node.node_type === 'internet' ? '#3b82f6' : item.node.node_type === 'gateway' ? '#6366f1' : item.node.node_type === 'dns' ? '#8b5cf6' : '#a855f7'}
									opacity="0.15"
								/>
								<circle
									r="20"
									fill={item.node.node_type === 'internet' ? '#3b82f6' : item.node.node_type === 'gateway' ? '#6366f1' : item.node.node_type === 'dns' ? '#8b5cf6' : '#a855f7'}
									opacity="0.8"
									filter="url(#glow)"
								/>
								<text text-anchor="middle" dy="6" fill="white" font-size="16">{item.node.icon}</text>
								<text text-anchor="middle" dy="38" fill="#f1f5f9" font-size="11" font-weight="600">{item.node.label.length > 16 ? item.node.label.slice(0, 16) + '...' : item.node.label}</text>
								{#if item.node.ip}
									<text text-anchor="middle" dy="52" fill="#94a3b8" font-size="9">{item.node.ip}</text>
								{/if}
								{#if item.node.risk_level && item.node.risk_level !== 'unknown' && item.node.risk_level !== 'info'}
									<circle cx="14" cy="-14" r="6" fill={riskColorMap[item.node.risk_level] || '#6b7280'} />
								{/if}
							</g>
						{/each}
					</svg>
				</div>
			{:else}
				<div class="empty-state"><p>{$tr('networkDiscovery.topology.noData')}</p></div>
			{/if}
		</div>
	{:else if activeTab === 'hosts'}
		<div class="section-card">
			<h2 class="section-title">{$tr('networkDiscovery.hosts.title')} ({result?.hosts.length || 0})</h2>
			{#if result && result.hosts.length > 0}
				<div class="hosts-table-wrapper">
					<table class="data-table">
						<thead>
							<tr>
								<th>{$tr('networkDiscovery.hosts.ip')}</th>
								<th>{$tr('networkDiscovery.hosts.hostname')}</th>
								<th>{$tr('networkDiscovery.hosts.mac')}</th>
								<th>{$tr('networkDiscovery.hosts.vendor')}</th>
								<th>{$tr('networkDiscovery.hosts.os')}</th>
								<th>{$tr('networkDiscovery.hosts.ports')}</th>
								<th>{$tr('networkDiscovery.hosts.risk')}</th>
								<th>{$tr('networkDiscovery.hosts.actions')}</th>
							</tr>
						</thead>
						<tbody>
							{#each result.hosts as host}
								<tr>
									<td class="mono">{host.ip}</td>
									<td>{host.hostname || '-'}</td>
									<td class="mono">{host.mac_address || '-'}</td>
									<td>{host.vendor || '-'}</td>
									<td>{host.os_guess || '-'}</td>
									<td>{host.ports.filter(p => p.state === 'open').map(p => p.port).join(', ') || '-'}</td>
									<td><span class="risk-badge {getRiskBadgeClass(host.risk_level)}">{getRiskLabel(host.risk_level)}</span></td>
									<td><button class="btn-small btn-detail" on:click={() => showHostInfo(host)}>👁️</button></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<div class="empty-state"><p>{$tr('networkDiscovery.hosts.noHosts')}</p></div>
			{/if}
		</div>
	{:else if activeTab === 'security'}
		<div class="section-card">
			<h2 class="section-title">{$tr('networkDiscovery.security.title')} ({result?.security_findings.length || 0})</h2>
			{#if result && result.security_findings.length > 0}
				<div class="findings-list">
					{#each result.security_findings as finding}
						<div class="finding-card {getSeverityClass(finding.severity)}">
							<div class="finding-header">
								<span class="severity-badge {getSeverityClass(finding.severity)}">{finding.severity.toUpperCase()}</span>
								<span class="finding-category">{finding.category}</span>
								<span class="finding-host mono">{finding.affected_host}</span>
							</div>
							<div class="finding-body">
								<p class="finding-desc">{finding.description}</p>
								<p class="finding-rec">💡 {finding.recommendation}</p>
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<div class="empty-state"><p>{$tr('networkDiscovery.security.noFindings')}</p></div>
			{/if}
		</div>
	{:else if activeTab === 'history'}
		<div class="history-section">
			<div class="history-header">
				<h2 class="section-title">{$tr('networkDiscovery.history.title')}</h2>
				<div class="history-actions">
					<button class="btn-small btn-secondary" on:click={loadHistory} disabled={loadingHistory}>🔄 {$tr('networkDiscovery.history.refresh')}</button>
					<button class="btn-small btn-danger" on:click={clearAllHistory} disabled={loadingHistory || history.length === 0}>🗑️ {$tr('networkDiscovery.history.clearAll')}</button>
				</div>
			</div>
			{#if historyError}
				<div class="error-card"><p>{historyError}</p></div>
			{:else if loadingHistory}
				<div class="loading-state">{$tr('common.loading')}</div>
			{:else if history.length === 0}
				<div class="empty-state"><p>{$tr('networkDiscovery.history.empty')}</p><p class="empty-hint">{$tr('networkDiscovery.history.hint')}</p></div>
			{:else}
				<div class="history-table-wrapper">
					<table class="data-table">
						<thead>
							<tr>
								<th>{$tr('networkDiscovery.history.table.range')}</th>
								<th>{$tr('networkDiscovery.history.table.activeHosts')}</th>
								<th>{$tr('networkDiscovery.history.table.scanned')}</th>
								<th>{$tr('networkDiscovery.history.table.time')}</th>
								<th>{$tr('networkDiscovery.history.table.actions')}</th>
							</tr>
						</thead>
						<tbody>
							{#each history as item}
								<tr>
									<td class="mono">{item.network_range}</td>
									<td>{item.active_hosts}</td>
									<td>{item.total_scanned}</td>
									<td>{new Date(item.created_at).toLocaleString()}</td>
									<td class="actions-cell">
										<button class="btn-small btn-secondary" on:click={() => rescanFromHistory(item)} title={$tr('networkDiscovery.history.rescan')}>🔄</button>
										<button class="btn-small btn-detail" on:click={() => viewHistoryDetail(item)} title={$tr('networkDiscovery.history.viewDetail')}>👁️</button>
										<button class="btn-small btn-danger" on:click={() => deleteHistoryItem(item.id)} title={$tr('networkDiscovery.history.deleteRecord')}>🗑️</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<div class="history-pagination">
					<button class="pagination-btn" disabled={historyCurrentPage === 1} on:click={() => { historyCurrentPage--; loadHistory(); }}>←</button>
					<span class="pagination-info">{historyCurrentPage}</span>
					<button class="pagination-btn" disabled={history.length < historyPageSize} on:click={() => { historyCurrentPage++; loadHistory(); }}>→</button>
				</div>
			{/if}
		</div>
	{/if}
</div>

{#if showHostDetail && selectedHost}
	<div class="modal-overlay" on:click={() => showHostDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHostDetail = false)}>
		<div class="modal-content" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('networkDiscovery.hostDetail.title')} - {selectedHost.ip}</h2>
				<button class="modal-close" on:click={() => showHostDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="detail-section">
					<h4>{$tr('networkDiscovery.hostDetail.basicInfo')}</h4>
					<div class="detail-grid">
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hostDetail.ip')}</span><span class="detail-value mono">{selectedHost.ip}</span></div>
						{#if selectedHost.hostname}<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hosts.hostname')}</span><span class="detail-value">{selectedHost.hostname}</span></div>{/if}
						{#if selectedHost.mac_address}<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hostDetail.mac')}</span><span class="detail-value mono">{selectedHost.mac_address}</span></div>{/if}
						{#if selectedHost.vendor}<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hosts.vendor')}</span><span class="detail-value">{selectedHost.vendor}</span></div>{/if}
						{#if selectedHost.os_guess}<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hostDetail.os')}</span><span class="detail-value">{selectedHost.os_guess}</span></div>{/if}
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hosts.risk')}</span><span class="risk-badge {getRiskBadgeClass(selectedHost.risk_level)}">{getRiskLabel(selectedHost.risk_level)}</span></div>
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.hostDetail.responseTime')}</span><span class="detail-value">{selectedHost.response_time_ms}ms</span></div>
					</div>
				</div>
				{#if selectedHost.ports.length > 0}
					<div class="detail-section">
						<h4>{$tr('networkDiscovery.hostDetail.openPorts')}</h4>
						<div class="ports-table-wrapper">
							<table class="data-table">
								<thead><tr><th>{$tr('networkDiscovery.hostDetail.port')}</th><th>{$tr('networkDiscovery.hostDetail.protocol')}</th><th>{$tr('networkDiscovery.hostDetail.state')}</th><th>{$tr('networkDiscovery.hostDetail.service')}</th><th>{$tr('networkDiscovery.hostDetail.version')}</th></tr></thead>
								<tbody>
									{#each selectedHost.ports as port}
										<tr>
											<td class="mono">{port.port}</td>
											<td>{port.protocol}</td>
											<td><span class="port-state {port.state}">{port.state}</span></td>
											<td>{port.service}</td>
											<td>{port.version || '-'}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					</div>
				{/if}
				{#if selectedHost.services.length > 0}
					<div class="detail-section">
						<h4>{$tr('networkDiscovery.hostDetail.services')}</h4>
						<div class="services-list">
							{#each selectedHost.services as svc}
								<span class="service-tag">{svc.name} ({svc.port}){svc.version ? ` - ${svc.version}` : ''}</span>
							{/each}
						</div>
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<button class="btn-secondary" on:click={() => showHostDetail = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showHistoryDetail && selectedHistoryItem}
	<div class="modal-overlay" on:click={() => showHistoryDetail = false} on:keydown={(e) => e.key === 'Escape' && (showHistoryDetail = false)}>
		<div class="modal-content" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('networkDiscovery.history.detailTitle')}</h2>
				<button class="modal-close" on:click={() => showHistoryDetail = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="detail-section">
					<h4>{$tr('networkDiscovery.history.detailInfo')}</h4>
					<div class="detail-grid">
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.history.table.range')}</span><span class="detail-value mono">{selectedHistoryItem.network_range}</span></div>
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.result.active')}</span><span class="detail-value">{selectedHistoryItem.active_hosts}</span></div>
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.result.scanned')}</span><span class="detail-value">{selectedHistoryItem.total_scanned}</span></div>
						<div class="detail-item"><span class="detail-label">{$tr('networkDiscovery.history.table.time')}</span><span class="detail-value">{new Date(selectedHistoryItem._created_at).toLocaleString()}</span></div>
					</div>
				</div>
				{#if selectedHistoryItem.summary}
					<div class="detail-section">
						<h4>{$tr('networkDiscovery.history.detailSummary')}</h4>
						<p class="detail-summary">{selectedHistoryItem.summary}</p>
					</div>
				{/if}
				{#if selectedHistoryItem.hosts && selectedHistoryItem.hosts.length > 0}
					<div class="detail-section">
						<h4>{$tr('networkDiscovery.hosts.title')} ({selectedHistoryItem.hosts.length})</h4>
						<div class="detail-hosts-list">
							{#each selectedHistoryItem.hosts as host}
								<div class="detail-host-item">
									<span class="host-ip mono">{host.ip}</span>
									<span class="host-name">{host.hostname || host.vendor || '-'}</span>
									<span class="risk-badge {getRiskBadgeClass(host.risk_level)}">{getRiskLabel(host.risk_level)}</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}
			</div>
			<div class="modal-footer">
				<button class="btn-primary" on:click={() => { showHistoryDetail = false; rescanFromDetail(selectedHistoryItem); }}>
					🔄 {$tr('networkDiscovery.history.rescan')}
				</button>
				<button class="btn-secondary" on:click={() => showHistoryDetail = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

{#if showHelpModal}
	<div class="modal-overlay" on:click={() => showHelpModal = false} on:keydown={(e) => e.key === 'Escape' && (showHelpModal = false)}>
		<div class="modal-content help-modal" on:click|stopPropagation on:keydown|stopPropagation>
			<div class="modal-header">
				<h2>{$tr('networkDiscovery.help.title')}</h2>
				<button class="modal-close" on:click={() => showHelpModal = false}>✕</button>
			</div>
			<div class="modal-body">
				<div class="help-section">
					<h3>{$tr('networkDiscovery.help.whatIsNetworkDiscovery')}</h3>
					<p>{$tr('networkDiscovery.help.whatIsNetworkDiscoveryDesc')}</p>
				</div>
				<div class="help-section">
					<h3>{$tr('networkDiscovery.help.howToUse')}</h3>
					<ul>
						<li>{$tr('networkDiscovery.help.step1')}</li>
						<li>{$tr('networkDiscovery.help.step2')}</li>
						<li>{$tr('networkDiscovery.help.step3')}</li>
						<li>{$tr('networkDiscovery.help.step4')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('networkDiscovery.help.features')}</h3>
					<ul>
						<li>{$tr('networkDiscovery.help.feature1')}</li>
						<li>{$tr('networkDiscovery.help.feature2')}</li>
						<li>{$tr('networkDiscovery.help.feature3')}</li>
						<li>{$tr('networkDiscovery.help.feature4')}</li>
						<li>{$tr('networkDiscovery.help.feature5')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('networkDiscovery.help.topologyTitle')}</h3>
					<ul>
						<li>{$tr('networkDiscovery.help.topology1')}</li>
						<li>{$tr('networkDiscovery.help.topology2')}</li>
						<li>{$tr('networkDiscovery.help.topology3')}</li>
					</ul>
				</div>
				<div class="help-section">
					<h3>{$tr('networkDiscovery.help.warningTitle')}</h3>
					<ul>
						<li>{$tr('networkDiscovery.help.warning1')}</li>
						<li>{$tr('networkDiscovery.help.warning2')}</li>
						<li>{$tr('networkDiscovery.help.warning3')}</li>
					</ul>
				</div>
			</div>
			<div class="modal-footer">
				<button class="btn-primary" on:click={() => showHelpModal = false}>{$tr('common.close')}</button>
			</div>
		</div>
	</div>
{/if}

<style>
	:global(*) {
		box-sizing: border-box;
	}

	.nd-page {
		padding: 1.5rem 2rem;
		max-width: 1400px;
		margin: 0 auto;
		min-height: 100vh;
		color: #e2e8f0;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.header-left {
		display: flex;
		align-items: baseline;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.back-link {
		color: #94a3b8;
		text-decoration: none;
		font-size: 0.85rem;
		transition: color 0.2s;
	}

	.back-link:hover {
		color: #a855f7;
	}

	.page-title {
		font-size: 1.5rem;
		font-weight: 700;
		margin: 0;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.page-subtitle {
		color: #94a3b8;
		font-size: 0.85rem;
		margin: 0;
	}

	.header-actions {
		display: flex;
		gap: 0.5rem;
	}

	.help-button {
		width: 2.25rem;
		height: 2.25rem;
		border-radius: 50%;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #a855f7;
		cursor: pointer;
		font-size: 0.9rem;
		font-weight: 700;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all 0.2s;
	}

	.help-button:hover {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
		transform: scale(1.05);
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1.5rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 0.25rem;
	}

	.tab-button {
		padding: 0.6rem 1.25rem;
		background: transparent;
		border: none;
		color: #94a3b8;
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		border-radius: 0.5rem;
		position: relative;
		white-space: nowrap;
	}

	.tab-button:hover:not(.active):not(:disabled) {
		color: #c4b5fd;
		background: rgba(168, 85, 247, 0.08);
	}

	.tab-button.active {
		color: white;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		font-weight: 600;
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
	}

	.tab-button:disabled {
		opacity: 0.35;
		cursor: not-allowed;
	}

	.content-grid {
		display: grid;
		grid-template-columns: 380px 1fr;
		gap: 1.5rem;
		align-items: start;
	}

	.config-section {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.section-card {
		background: rgba(10, 14, 23, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.75rem;
		padding: 1.5rem;
	}

	.section-title {
		font-size: 1.1rem;
		font-weight: 600;
		margin: 0 0 1.25rem;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.form-group {
		margin-bottom: 0.875rem;
	}

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.form-label {
		display: block;
		font-size: 0.8rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.form-input {
		width: 100%;
		padding: 0.5rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.875rem;
		box-sizing: border-box;
		transition: all 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: rgba(168, 85, 247, 0.5);
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.1);
	}

	.form-input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	select.form-input {
		appearance: none;
		background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23a855f7' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E");
		background-repeat: no-repeat;
		background-position: right 0.75rem center;
		padding-right: 2rem;
	}

	.checkbox-group {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		margin-top: 1.25rem;
	}

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.85rem;
		color: #cbd5e1;
		cursor: pointer;
	}

	.checkbox-label input[type="checkbox"] {
		accent-color: #a855f7;
		width: 1rem;
		height: 1rem;
	}

	.button-group {
		display: flex;
		gap: 0.75rem;
		margin-top: 1.25rem;
	}

	.btn-primary {
		flex: 1;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		padding: 0.65rem 1.25rem;
		border: none;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		font-size: 0.9rem;
	}

	.btn-primary:hover:not(:disabled) {
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		transform: none;
		box-shadow: none;
	}

	.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid #a855f7;
		color: #a855f7;
		font-weight: 600;
		padding: 0.65rem 1.25rem;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: #c084fc;
	}

	.btn-secondary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-danger {
		background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
		color: white;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-danger:hover:not(:disabled) {
		transform: translateY(-1px);
		box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
	}

	.btn-danger:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-small {
		padding: 0.35rem 0.65rem;
		font-size: 0.8rem;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: all 0.2s;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.25rem;
	}

	.btn-small.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.3);
		color: #a855f7;
		padding: 0.35rem 0.65rem;
		font-weight: 500;
	}

	.btn-small.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: #c084fc;
	}

	.btn-small.btn-danger {
		background: rgba(239, 68, 68, 0.15);
		border: 1px solid rgba(239, 68, 68, 0.3);
		color: #ef4444;
		padding: 0.35rem 0.65rem;
	}

	.btn-small.btn-danger:hover:not(:disabled) {
		background: rgba(239, 68, 68, 0.25);
		border-color: rgba(239, 68, 68, 0.5);
	}

	.btn-detail {
		background: rgba(168, 85, 247, 0.15);
		color: #a855f7;
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.btn-detail:hover {
		background: rgba(168, 85, 247, 0.25);
		border-color: rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-view-topology {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border: none;
		border-radius: 0.5rem;
		cursor: pointer;
		font-size: 0.85rem;
		font-weight: 600;
		transition: all 0.2s;
		margin-top: 0.75rem;
	}

	.btn-view-topology:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
	}

	.spinner {
		width: 1rem;
		height: 1rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		display: inline-block;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 0.5rem;
		margin-bottom: 1rem;
	}

	.error-icon {
		font-size: 1.25rem;
	}

	.error-message {
		color: #fca5a5;
		font-size: 0.9rem;
	}

	.result-summary {
		padding: 0.875rem 1rem;
		border-radius: 0.5rem;
		margin-bottom: 1rem;
		font-size: 0.9rem;
		line-height: 1.5;
		background: rgba(99, 102, 241, 0.1);
		border: 1px solid rgba(99, 102, 241, 0.2);
		color: #c7d2fe;
	}

	.scan-stats {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.stat-badge {
		padding: 0.3rem 0.65rem;
		background: rgba(99, 102, 241, 0.15);
		border: 1px solid rgba(99, 102, 241, 0.2);
		border-radius: 9999px;
		font-size: 0.75rem;
		color: #a5b4fc;
		font-weight: 500;
	}

	.stat-active {
		background: rgba(34, 197, 94, 0.15);
		border-color: rgba(34, 197, 94, 0.2);
		color: #86efac;
	}

	.stat-finding {
		background: rgba(245, 158, 11, 0.15);
		border-color: rgba(245, 158, 11, 0.2);
		color: #fcd34d;
	}

	.topology-info {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.info-item {
		display: flex;
		justify-content: space-between;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.375rem;
		font-size: 0.85rem;
	}

	.info-label {
		color: #94a3b8;
	}

	.info-value {
		font-weight: 500;
		color: #f1f5f9;
		font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
		font-size: 0.8rem;
	}

	.mini-topology-preview {
		margin-top: 1rem;
		padding: 1rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.5rem;
		text-align: center;
	}

	.mini-topology-preview h4 {
		margin: 0 0 0.75rem;
		font-size: 0.85rem;
		color: #a855f7;
		font-weight: 600;
	}

	.topology-svg-mini {
		width: 100%;
		max-height: 180px;
	}

	.topology-legend {
		display: flex;
		gap: 1rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
		padding: 0.75rem 1rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.5rem;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.legend-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		display: inline-block;
	}

	.legend-line {
		width: 20px;
		height: 2px;
		background: #4b5563;
		display: inline-block;
	}

	.legend-line.dashed {
		background: transparent;
		border-top: 2px dashed #8b5cf6;
	}

	.topology-container {
		overflow: auto;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.5rem;
		padding: 1.5rem;
	}

	.topology-svg {
		width: 100%;
		min-height: 400px;
	}

	.topology-node {
		cursor: pointer;
	}

	.topology-node:hover circle {
		opacity: 1;
	}

	.hosts-table-wrapper, .history-table-wrapper {
		overflow-x: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.data-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	.data-table th {
		padding: 0.6rem 0.75rem;
		text-align: left;
		border-bottom: 1px solid rgba(168, 85, 247, 0.2);
		background: rgba(168, 85, 247, 0.08);
		color: #a855f7;
		font-weight: 600;
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		white-space: nowrap;
	}

	.data-table td {
		padding: 0.6rem 0.75rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.08);
		color: #d1d5db;
		font-size: 0.8rem;
	}

	.data-table tr:hover {
		background: rgba(168, 85, 247, 0.05);
	}

	.mono {
		font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
		font-size: 0.8rem;
		color: #60a5fa;
	}

	.risk-badge {
		padding: 0.2rem 0.5rem;
		border-radius: 9999px;
		font-size: 0.7rem;
		font-weight: 600;
		display: inline-block;
	}

	.risk-high {
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.3);
	}

	.risk-medium {
		background: rgba(245, 158, 11, 0.15);
		color: #f59e0b;
		border: 1px solid rgba(245, 158, 11, 0.3);
	}

	.risk-low {
		background: rgba(34, 197, 94, 0.15);
		color: #22c55e;
		border: 1px solid rgba(34, 197, 94, 0.3);
	}

	.risk-unknown {
		background: rgba(107, 114, 128, 0.15);
		color: #6b7280;
		border: 1px solid rgba(107, 114, 128, 0.3);
	}

	.actions-cell {
		white-space: nowrap;
	}

	.actions-cell .btn-small {
		margin-right: 0.25rem;
	}

	.findings-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.finding-card {
		padding: 1rem;
		border-radius: 0.5rem;
		border-left: 4px solid;
		background: rgba(15, 23, 42, 0.5);
	}

	.finding-card.severity-high {
		border-left-color: #ef4444;
		background: rgba(239, 68, 68, 0.05);
	}

	.finding-card.severity-medium {
		border-left-color: #f59e0b;
		background: rgba(245, 158, 11, 0.05);
	}

	.finding-card.severity-low {
		border-left-color: #22c55e;
		background: rgba(34, 197, 94, 0.05);
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.5rem;
	}

	.severity-badge {
		padding: 0.2rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.65rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.severity-badge.severity-high {
		background: #ef4444;
		color: white;
	}

	.severity-badge.severity-medium {
		background: #f59e0b;
		color: white;
	}

	.severity-badge.severity-low {
		background: #22c55e;
		color: white;
	}

	.finding-category {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.finding-host {
		color: #94a3b8;
		font-size: 0.8rem;
		font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
	}

	.finding-desc {
		font-size: 0.85rem;
		color: #d1d5db;
		margin: 0 0 0.375rem;
		line-height: 1.5;
	}

	.finding-rec {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #94a3b8;
	}

	.empty-state p {
		margin: 0;
		font-size: 0.9rem;
	}

	.empty-icon {
		font-size: 2.5rem;
		margin-bottom: 0.75rem;
	}

	.empty-hint {
		font-size: 0.8rem;
		margin-top: 0.5rem;
		color: #64748b;
	}

	.loading-state {
		text-align: center;
		padding: 3rem;
		color: #94a3b8;
		font-size: 0.9rem;
	}

	.history-section {
		background: rgba(10, 14, 23, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.75rem;
		padding: 1.5rem;
	}

	.history-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1.25rem;
	}

	.history-header .section-title {
		margin: 0;
	}

	.history-actions {
		display: flex;
		gap: 0.5rem;
	}

	.history-pagination {
		display: flex;
		justify-content: center;
		align-items: center;
		gap: 0.75rem;
		margin-top: 1.25rem;
	}

	.pagination-btn {
		padding: 0.35rem 0.75rem;
		border-radius: 0.375rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
		color: #a855f7;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.85rem;
	}

	.pagination-btn:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: #c084fc;
	}

	.pagination-btn:disabled {
		opacity: 0.35;
		cursor: not-allowed;
	}

	.pagination-info {
		font-size: 0.85rem;
		color: #94a3b8;
		min-width: 2rem;
		text-align: center;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.85);
		display: flex;
		justify-content: center;
		align-items: center;
		z-index: 1000;
		padding: 2rem;
		overflow-y: auto;
		backdrop-filter: blur(4px);
	}

	.modal-content {
		background: #1a1a2e;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.75rem;
		max-width: 700px;
		width: 100%;
		max-height: 90vh;
		overflow-y: auto;
		box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.25rem 1.5rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.2);
		position: sticky;
		top: 0;
		background: #1a1a2e;
		z-index: 10;
	}

	.modal-header h2 {
		font-size: 1.15rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0;
	}

	.modal-close {
		background: rgba(239, 68, 68, 0.15);
		border: 1px solid rgba(239, 68, 68, 0.3);
		color: #ef4444;
		width: 2rem;
		height: 2rem;
		border-radius: 0.375rem;
		cursor: pointer;
		font-size: 1rem;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all 0.2s;
		padding: 0;
	}

	.modal-close:hover {
		background: rgba(239, 68, 68, 0.25);
		border-color: rgba(239, 68, 68, 0.5);
	}

	.modal-body {
		padding: 1.5rem;
	}

	.modal-footer {
		padding: 0.75rem 1.5rem;
		border-top: 1px solid rgba(168, 85, 247, 0.2);
		display: flex;
		justify-content: flex-end;
		gap: 0.75rem;
		background: #1a1a2e;
		position: sticky;
		bottom: 0;
	}

	.modal-footer .btn-primary {
		flex: unset;
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
	}

	.modal-footer .btn-secondary {
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
	}

	.detail-section {
		margin-bottom: 1.25rem;
	}

	.detail-section:last-child {
		margin-bottom: 0;
	}

	.detail-section h4 {
		font-size: 0.9rem;
		font-weight: 600;
		margin: 0 0 0.75rem;
		padding-bottom: 0.5rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
		color: #a855f7;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.375rem;
	}

	.detail-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.4rem 0.65rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
		font-size: 0.8rem;
	}

	.detail-label {
		color: #94a3b8;
		font-size: 0.75rem;
	}

	.detail-value {
		font-weight: 500;
		color: #f1f5f9;
	}

	.ports-table-wrapper {
		overflow-x: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.2);
	}

	.port-state {
		padding: 0.125rem 0.5rem;
		border-radius: 9999px;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: capitalize;
	}

	.port-state.open {
		background: rgba(34, 197, 94, 0.2);
		color: #22c55e;
		border: 1px solid rgba(34, 197, 94, 0.3);
	}

	.port-state.closed {
		background: rgba(239, 68, 68, 0.2);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.3);
	}

	.services-list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
	}

	.service-tag {
		padding: 0.2rem 0.5rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.375rem;
		font-size: 0.75rem;
		color: #c4b5fd;
	}

	.detail-summary {
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
		font-size: 0.85rem;
		color: #d1d5db;
		line-height: 1.6;
	}

	.detail-hosts-list {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.detail-host-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.4rem 0.65rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
		font-size: 0.8rem;
	}

	.host-ip {
		font-weight: 600;
		color: #60a5fa;
		font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
		font-size: 0.8rem;
	}

	.host-name {
		color: #94a3b8;
		flex: 1;
	}

	.help-modal {
		max-width: 800px;
	}

	.help-modal .modal-body {
		max-height: 70vh;
		overflow-y: auto;
	}

	.help-section {
		margin-bottom: 1.25rem;
	}

	.help-section:last-child {
		margin-bottom: 0;
	}

	.help-section h3 {
		font-size: 1rem;
		font-weight: 600;
		color: #a855f7;
		margin: 0 0 0.75rem;
		padding-bottom: 0.5rem;
		border-bottom: 2px solid rgba(168, 85, 247, 0.2);
	}

	.help-section p {
		font-size: 0.875rem;
		color: #cbd5e1;
		line-height: 1.6;
		margin: 0 0 0.5rem;
	}

	.help-section ul {
		list-style: none;
		padding: 0;
		margin: 0.5rem 0;
	}

	.help-section li {
		font-size: 0.825rem;
		color: #cbd5e1;
		margin-bottom: 0.5rem;
		line-height: 1.5;
		padding-left: 1.25rem;
		position: relative;
	}

	.help-section li::before {
		content: '▸';
		position: absolute;
		left: 0;
		color: #a855f7;
	}

	@media (max-width: 768px) {
		.nd-page {
			padding: 1rem;
		}

		.content-grid {
			grid-template-columns: 1fr;
		}

		.form-row {
			grid-template-columns: 1fr;
		}

		.detail-grid {
			grid-template-columns: 1fr;
		}

		.topology-info {
			grid-template-columns: 1fr;
		}

		.page-header {
			flex-direction: column;
			align-items: flex-start;
			gap: 0.75rem;
		}

		.tabs {
			overflow-x: auto;
		}
	}
</style>
