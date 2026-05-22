<script lang="ts">
	import { tr } from '$lib/i18n';
	import { onMount } from 'svelte';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface WifiNetwork {
		ssid: string;
		bssid: string;
		signal_strength: number;
		channel: number;
		encryption: string;
		frequency: string;
		band: string;
		is_hidden: boolean;
		security_score: number;
		security_notes: string[];
	}

	interface WifiSecuritySummary {
		total_networks: number;
		open_networks: number;
		wep_networks: number;
		wpa_networks: number;
		wpa2_networks: number;
		wpa3_networks: number;
		hidden_networks: number;
		weak_signal_networks: number;
		overall_risk: string;
	}

	interface WifiVulnerability {
		severity: string;
		category: string;
		description: string;
		affected_network: string;
		recommendation: string;
	}

	interface WifiScanResult {
		success: boolean;
		interface: string;
		networks: WifiNetwork[];
		security_summary: WifiSecuritySummary;
		vulnerabilities: WifiVulnerability[];
		summary: string;
		is_demo: boolean;
	}

	interface CrackResult {
		ssid: string;
		bssid: string;
		encryption: string;
		crackable: boolean;
		crack_method: string;
		crack_time_estimate: string;
		confidence: number;
		details: string;
	}

	interface NetworkInterfaceInfo {
		name: string;
		display_name: string;
		is_wifi: boolean;
		is_up: boolean;
		mac_address: string;
		ip_address: string | null;
	}

	interface AutoCrackResult {
		ssid: string;
		bssid: string;
		encryption: string;
		crackable: boolean;
		cracked: boolean;
		method: string;
		password: string | null;
		time_taken: string;
		details: string;
	}

	let interface_ = $state('');
	let interfaces: NetworkInterfaceInfo[] = $state([]);
	let interfacesLoaded = $state(false);
	let timeout = $state(30);
	let scanHidden = $state(true);
	let detailedAnalysis = $state(true);
	let result: WifiScanResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('scan');
	let activeResultTab = $state('overview');
	let networkFilter = $state('all');

	let selectedNetwork: WifiNetwork | null = $state(null);
	let showNetworkDetail = $state(false);
	let showConnectModal = $state(false);
	let connectPassword = $state('');
	let connecting = $state(false);
	let connectError = $state('');
	let connectSuccess = $state(false);

	let cracking = $state(false);
	let crackResults: CrackResult[] = $state([]);
	let crackError = $state('');
	let selectedCrackNetwork: CrackResult | null = $state(null);
	let showCrackDetail = $state(false);

	let autoCracking = $state(false);
	let autoCrackResults: AutoCrackResult[] = $state([]);
	let autoCrackError = $state('');
	let showAutoCrackResult = $state(false);

	let autoConnectEnabled = $state(false);
	let autoConnectSsid = $state('');

	let historyComponent: ToolHistory = $state(null!);

	onMount(async () => {
		await loadInterfaces();
	});

	async function loadInterfaces() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			interfaces = await invoke<NetworkInterfaceInfo[]>('list_wifi_interfaces_command');
			interfacesLoaded = true;
			if (interface_ === '' && interfaces.length > 0) {
				const wifiIf = interfaces.find(i => i.is_wifi);
				if (wifiIf) {
					interface_ = wifiIf.name;
				}
			}
		} catch (e: any) {
			interfacesLoaded = true;
		}
	}

	async function scan() {
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<WifiScanResult>('scan_wifi_command', {
				config: {
					interface: interface_.trim(),
					timeout,
					scan_hidden: scanHidden,
					detailed_analysis: detailedAnalysis,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(interface_.trim() || $tr('wifiScanner.title'), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(interface_.trim() || $tr('wifiScanner.title'), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	async function connectToNetwork(net: WifiNetwork) {
		selectedNetwork = net;
		connectPassword = '';
		connectError = '';
		connectSuccess = false;
		if (net.encryption === 'Open') {
			await doConnect('');
		} else {
			showConnectModal = true;
		}
	}

	async function doConnect(password: string) {
		connecting = true; connectError = ''; connectSuccess = false;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			await invoke('connect_wifi_command', {
				config: {
					ssid: selectedNetwork!.ssid,
					bssid: selectedNetwork!.bssid,
					password,
					interface: interface_.trim() || result?.interface || 'en0',
				}
			});
			connectSuccess = true;
			if (autoConnectEnabled) {
				autoConnectSsid = selectedNetwork!.ssid;
			}
		} catch (e: any) {
			connectError = e.toString();
		} finally { connecting = false; }
	}

	async function startCrackDiscovery() {
		if (!result || result.networks.length === 0) return;
		cracking = true; crackError = ''; crackResults = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			crackResults = await invoke<CrackResult[]>('wifi_crack_discovery_command', {
				networks: result.networks,
			});
		} catch (e: any) {
			crackError = e.toString();
		} finally { cracking = false; }
	}

	async function startAutoCrack() {
		if (!result || result.networks.length === 0) return;
		autoCracking = true; autoCrackError = ''; autoCrackResults = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			autoCrackResults = await invoke<AutoCrackResult[]>('wifi_auto_crack_command', {
				networks: result.networks,
			});
			showAutoCrackResult = true;
		} catch (e: any) {
			autoCrackError = e.toString();
		} finally { autoCracking = false; }
	}

	async function autoCrackAndConnect(cr: AutoCrackResult) {
		if (!cr.cracked || cr.encryption === 'Open') {
			const net = result?.networks.find(n => n.bssid === cr.bssid);
			if (net) await connectToNetwork(net);
			return;
		}
		selectedNetwork = result?.networks.find(n => n.bssid === cr.bssid) || null;
		if (selectedNetwork) {
			connectPassword = cr.password || '';
			await doConnect(cr.password || '');
			showConnectModal = true;
		}
	}

	function clearAll() {
		result = null; error = '';
		crackResults = []; crackError = '';
		autoCrackResults = []; autoCrackError = '';
		showAutoCrackResult = false;
	}

	function getFilteredNetworks(): WifiNetwork[] {
		if (!result) return [];
		switch (networkFilter) {
			case 'hidden': return result.networks.filter(n => n.is_hidden);
			case 'visible': return result.networks.filter(n => !n.is_hidden);
			case 'open': return result.networks.filter(n => n.encryption === 'Open');
			case 'weak': return result.networks.filter(n => n.security_score < 40);
			default: return result.networks;
		}
	}

	function getSignalBars(strength: number): string {
		if (strength >= -50) return '████';
		if (strength >= -60) return '███░';
		if (strength >= -70) return '██░░';
		return '█░░░';
	}

	function getSignalLevel(strength: number): string {
		if (strength >= -50) return 'excellent';
		if (strength >= -60) return 'good';
		if (strength >= -70) return 'fair';
		return 'weak';
	}

	function getEncryptionColor(enc: string): string {
		if (enc.includes('WPA3')) return '#22c55e';
		if (enc.includes('WPA2')) return '#3b82f6';
		if (enc.includes('WPA')) return '#eab308';
		if (enc.includes('WEP')) return '#f97316';
		if (enc.includes('Open') || enc.includes('open')) return '#ef4444';
		return '#6b7280';
	}

	function getSecurityScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#3b82f6';
		if (score >= 40) return '#eab308';
		if (score >= 20) return '#f97316';
		return '#ef4444';
	}

	function getRiskColor(risk: string): string {
		switch (risk) {
			case 'High': return '#ef4444';
			case 'Medium': return '#eab308';
			case 'Low': return '#3b82f6';
			case 'Safe': return '#22c55e';
			default: return '#6b7280';
		}
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#eab308';
			case 'low': return '#3b82f6';
			case 'info': return '#6b7280';
			default: return '#6b7280';
		}
	}

	function getCrackConfidenceColor(conf: number): string {
		if (conf >= 0.8) return '#ef4444';
		if (conf >= 0.5) return '#f97316';
		if (conf >= 0.3) return '#eab308';
		return '#22c55e';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📶 {$tr('wifiScanner.title')}</h1>
			<p class="page-subtitle">{$tr('wifiScanner.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'scan' ? 'active' : ''}" onclick={() => activeMainTab = 'scan'}>
			<span class="tab-icon">🔍</span> {$tr('wifiScanner.scan')}
		</button>
		<button class="tab-btn {activeMainTab === 'crack' ? 'active' : ''}" onclick={() => activeMainTab = 'crack'}>
			<span class="tab-icon">🔓</span> {$tr('wifiScanner.crackDiscovery')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('wifiScanner.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('wifiScanner.help')}
		</button>
	</div>

	{#if activeMainTab === 'scan'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('wifiScanner.scanConfig')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('wifiScanner.interface')}</label>
						{#if interfacesLoaded && interfaces.length > 0}
							<select bind:value={interface_} class="form-input" disabled={processing}>
								<option value="">{$tr('wifiScanner.allInterfaces')}</option>
								{#each interfaces as if_}
									<option value={if_.name}>
										{if_.display_name} ({if_.name}){if_.is_wifi ? ' 📶' : ''}{if_.is_up ? ' ✅' : ' ⏸'}{if_.ip_address ? ` - ${if_.ip_address}` : ''}
									</option>
								{/each}
							</select>
						{:else}
							<input type="text" bind:value={interface_} placeholder="en0" class="form-input" disabled={processing} />
						{/if}
						<button class="btn-refresh" onclick={loadInterfaces} disabled={processing} title={$tr('wifiScanner.refreshInterfaces')}>🔄</button>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('wifiScanner.timeout')}</label>
						<input type="number" bind:value={timeout} class="form-input" min="5" max="120" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={scanHidden} disabled={processing} />
							<span>{$tr('wifiScanner.scanHidden')}</span>
						</label>
					</div>
					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={detailedAnalysis} disabled={processing} />
							<span>{$tr('wifiScanner.detailedAnalysis')}</span>
						</label>
					</div>
					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={autoConnectEnabled} />
							<span>{$tr('wifiScanner.autoConnect')}</span>
						</label>
					</div>
					<div class="button-group">
						<button class="btn-primary" onclick={scan} disabled={processing}>
							{#if processing}<span class="spinner"></span>{$tr('wifiScanner.scanning')}{:else}📶 {$tr('wifiScanner.startScan')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>

				{#if result?.security_summary}
					<div class="section-card" style="margin-top: 1rem;">
						<h2 class="section-title">{$tr('wifiScanner.securityOverview')}</h2>
						<div class="risk-indicator" style="border-color: {getRiskColor(result.security_summary.overall_risk)}">
							<div class="risk-label">{$tr('wifiScanner.overallRisk')}</div>
							<div class="risk-value" style="color: {getRiskColor(result.security_summary.overall_risk)}">{result.security_summary.overall_risk}</div>
						</div>
						<div class="security-stats">
							<div class="stat-item">
								<span class="stat-label">{$tr('wifiScanner.totalNetworks')}</span>
								<span class="stat-value">{result.security_summary.total_networks}</span>
							</div>
							<div class="stat-item danger">
								<span class="stat-label">{$tr('wifiScanner.openNetworks')}</span>
								<span class="stat-value">{result.security_summary.open_networks}</span>
							</div>
							<div class="stat-item warning">
								<span class="stat-label">WEP</span>
								<span class="stat-value">{result.security_summary.wep_networks}</span>
							</div>
							<div class="stat-item warning">
								<span class="stat-label">WPA</span>
								<span class="stat-value">{result.security_summary.wpa_networks}</span>
							</div>
							<div class="stat-item info">
								<span class="stat-label">WPA2</span>
								<span class="stat-value">{result.security_summary.wpa2_networks}</span>
							</div>
							<div class="stat-item safe">
								<span class="stat-label">WPA3</span>
								<span class="stat-value">{result.security_summary.wpa3_networks}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('wifiScanner.hiddenNetworks')}</span>
								<span class="stat-value">{result.security_summary.hidden_networks}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('wifiScanner.weakSignal')}</span>
								<span class="stat-value">{result.security_summary.weak_signal_networks}</span>
							</div>
						</div>
					</div>
				{/if}
			</div>

			<div class="result-section">
				<div class="section-card">
					{#if error}
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					{:else if result}
						<div class="result-summary">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('wifiScanner.networkList')}</button>
							<button class="result-tab {activeResultTab === 'security' ? 'active' : ''}" onclick={() => activeResultTab = 'security'}>{$tr('wifiScanner.securityIssues')}</button>
						</div>

						{#if activeResultTab === 'overview'}
							{#if result.is_demo}
								<div class="demo-notice">
									<span class="demo-icon">ℹ️</span>
									<span class="demo-text">{$tr('wifiScanner.demoNotice')}</span>
								</div>
							{/if}
							<div class="filter-bar">
								<button class="filter-btn {networkFilter === 'all' ? 'active' : ''}" onclick={() => networkFilter = 'all'}>{$tr('wifiScanner.all')} ({result.networks.length})</button>
								<button class="filter-btn {networkFilter === 'visible' ? 'active' : ''}" onclick={() => networkFilter = 'visible'}>{$tr('wifiScanner.visible')} ({result.networks.filter(n => !n.is_hidden).length})</button>
								<button class="filter-btn {networkFilter === 'hidden' ? 'active' : ''}" onclick={() => networkFilter = 'hidden'}>{$tr('wifiScanner.hidden')} ({result.networks.filter(n => n.is_hidden).length})</button>
								<button class="filter-btn {networkFilter === 'open' ? 'active' : ''}" onclick={() => networkFilter = 'open'}>{$tr('wifiScanner.openNet')} ({result.networks.filter(n => n.encryption === 'Open').length})</button>
								<button class="filter-btn {networkFilter === 'weak' ? 'active' : ''}" onclick={() => networkFilter = 'weak'}>{$tr('wifiScanner.weakSec')} ({result.networks.filter(n => n.security_score < 40).length})</button>
							</div>
							{#if getFilteredNetworks().length > 0}
								<div class="network-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('wifiScanner.ssid')}</th>
												<th>{$tr('wifiScanner.signal')}</th>
												<th>{$tr('wifiScanner.channel')}</th>
												<th>{$tr('wifiScanner.encryption')}</th>
												<th>{$tr('wifiScanner.band')}</th>
												<th>{$tr('wifiScanner.securityScore')}</th>
												<th>{$tr('wifiScanner.actions')}</th>
											</tr>
										</thead>
										<tbody>
										{#each getFilteredNetworks() as net}
												<tr>
													<td>
														<div class="ssid-cell">
															<span class="ssid-name">{net.ssid || $tr('wifiScanner.hiddenSsid')}</span>
															{#if net.is_hidden}
																<span class="hidden-badge">{$tr('wifiScanner.hidden')}</span>
															{/if}
														</div>
													</td>
													<td>
														<div class="signal-cell">
															<span class="signal-bars" data-level={getSignalLevel(net.signal_strength)}>{getSignalBars(net.signal_strength)}</span>
															<span class="signal-db">{net.signal_strength} dBm</span>
														</div>
													</td>
													<td class="mono">{net.channel}</td>
													<td>
														<span class="encryption-badge" style="color: {getEncryptionColor(net.encryption)}; border-color: {getEncryptionColor(net.encryption)}40; background: {getEncryptionColor(net.encryption)}15">{net.encryption}</span>
													</td>
													<td>{net.band}</td>
													<td>
														<span class="score-badge" style="color: {getSecurityScoreColor(net.security_score)}; border-color: {getSecurityScoreColor(net.security_score)}40; background: {getSecurityScoreColor(net.security_score)}15">{net.security_score}</span>
													</td>
													<td class="actions-cell">
														<button class="btn-small btn-info" onclick={() => { selectedNetwork = net; showNetworkDetail = true; }} title={$tr('wifiScanner.viewDetail')}>👁️</button>
														<button class="btn-small btn-connect" onclick={() => connectToNetwork(net)} title={$tr('wifiScanner.connect')}>🔗</button>
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">📶</div>
									<p>{$tr('wifiScanner.noNetworks')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'security'}
							{#if result.vulnerabilities.length > 0}
								<div class="vuln-list">
									{#each result.vulnerabilities as vuln}
										<div class="vuln-card" style="border-left-color: {getSeverityColor(vuln.severity)}">
											<div class="vuln-header">
												<span class="severity-badge" style="background: {getSeverityColor(vuln.severity)}20; color: {getSeverityColor(vuln.severity)}; border: 1px solid {getSeverityColor(vuln.severity)}40">{vuln.severity.toUpperCase()}</span>
												<span class="vuln-category">{vuln.category}</span>
											</div>
											<p class="vuln-desc">{vuln.description}</p>
											<div class="vuln-footer">
												<span class="vuln-affected">🎯 {vuln.affected_network}</span>
												<span class="vuln-rec">💡 {vuln.recommendation}</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state safe">
									<div class="empty-icon">✅</div>
									<p>{$tr('wifiScanner.noVulnerabilities')}</p>
								</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📶</div>
							<p>{$tr('wifiScanner.clickToScan')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>

		{#if showNetworkDetail && selectedNetwork}
			<div class="modal-overlay" onclick={() => showNetworkDetail = false} onkeydown={(e) => e.key === 'Escape' && (showNetworkDetail = false)}>
				<div class="modal-content" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
					<div class="modal-header">
						<h2>{$tr('wifiScanner.networkDetail')} - {selectedNetwork.ssid || $tr('wifiScanner.hiddenSsid')}</h2>
						<button class="modal-close" onclick={() => showNetworkDetail = false}>✕</button>
					</div>
					<div class="modal-body">
						<div class="detail-section">
							<h4>{$tr('wifiScanner.basicInfo')}</h4>
							<div class="detail-grid">
								<div class="detail-item">
									<span class="detail-label">SSID</span>
									<span class="detail-value mono">{selectedNetwork.ssid || $tr('wifiScanner.hiddenSsid')}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">BSSID</span>
									<span class="detail-value mono">{selectedNetwork.bssid}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.channel')}</span>
									<span class="detail-value">{selectedNetwork.channel}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.frequency')}</span>
									<span class="detail-value">{selectedNetwork.frequency}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.band')}</span>
									<span class="detail-value">{selectedNetwork.band}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.signal')}</span>
									<span class="detail-value">{selectedNetwork.signal_strength} dBm ({getSignalBars(selectedNetwork.signal_strength)})</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.encryption')}</span>
									<span class="detail-value" style="color: {getEncryptionColor(selectedNetwork.encryption)}">{selectedNetwork.encryption}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.securityScore')}</span>
									<span class="detail-value" style="color: {getSecurityScoreColor(selectedNetwork.security_score)}">{selectedNetwork.security_score}/100</span>
								</div>
							</div>
						</div>
						{#if selectedNetwork.security_notes.length > 0}
							<div class="detail-section">
								<h4>{$tr('wifiScanner.securityNotes')}</h4>
								<div class="notes-list">
									{#each selectedNetwork.security_notes as note}
										<div class="note-item">▸ {note}</div>
									{/each}
								</div>
							</div>
						{/if}
					</div>
					<div class="modal-footer">
						<button class="btn-secondary" onclick={() => showNetworkDetail = false}>{$tr('wifiScanner.close')}</button>
						<button class="btn-primary" onclick={() => { showNetworkDetail = false; connectToNetwork(selectedNetwork!); }}>🔗 {$tr('wifiScanner.connect')}</button>
					</div>
				</div>
			</div>
		{/if}

		{#if showConnectModal && selectedNetwork}
			<div class="modal-overlay" onclick={() => showConnectModal = false} onkeydown={(e) => e.key === 'Escape' && (showConnectModal = false)}>
				<div class="modal-content" style="max-width: 450px;" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
					<div class="modal-header">
						<h2>🔗 {$tr('wifiScanner.connectTo')} {selectedNetwork.ssid}</h2>
						<button class="modal-close" onclick={() => showConnectModal = false}>✕</button>
					</div>
					<div class="modal-body">
						{#if connectSuccess}
							<div class="connect-success">
								<div class="success-icon">✅</div>
								<p>{$tr('wifiScanner.connectSuccess')}</p>
							</div>
						{:else}
							<div class="connect-info">
								<div class="connect-detail">
									<span class="detail-label">SSID</span>
									<span class="detail-value mono">{selectedNetwork.ssid}</span>
								</div>
								<div class="connect-detail">
									<span class="detail-label">{$tr('wifiScanner.encryption')}</span>
									<span class="detail-value" style="color: {getEncryptionColor(selectedNetwork.encryption)}">{selectedNetwork.encryption}</span>
								</div>
								<div class="connect-detail">
									<span class="detail-label">{$tr('wifiScanner.signal')}</span>
									<span class="detail-value">{selectedNetwork.signal_strength} dBm</span>
								</div>
							</div>
							{#if selectedNetwork.encryption !== 'Open'}
								<div class="form-group" style="margin-top: 1rem;">
									<label class="form-label">🔑 {$tr('wifiScanner.password')}</label>
									<input type="password" bind:value={connectPassword} placeholder={$tr('wifiScanner.enterPassword')} class="form-input" disabled={connecting} />
								</div>
							{/if}
							{#if connectError}
								<div class="error-card" style="margin-top: 0.75rem;">
									<span class="error-icon">⚠️</span>
									<span class="error-text">{connectError}</span>
								</div>
							{/if}
						{/if}
					</div>
					{#if !connectSuccess}
						<div class="modal-footer">
							<button class="btn-secondary" onclick={() => showConnectModal = false} disabled={connecting}>{$tr('wifiScanner.cancel')}</button>
							<button class="btn-primary" onclick={() => doConnect(connectPassword)} disabled={connecting || (selectedNetwork.encryption !== 'Open' && !connectPassword)}>
								{#if connecting}<span class="spinner"></span>{$tr('wifiScanner.connecting')}{:else}🔗 {$tr('wifiScanner.connect')}{/if}
							</button>
						</div>
					{:else}
						<div class="modal-footer">
							<button class="btn-primary" onclick={() => showConnectModal = false}>{$tr('wifiScanner.close')}</button>
						</div>
					{/if}
				</div>
			</div>
		{/if}

	{:else if activeMainTab === 'crack'}
		<div class="content-grid" style="grid-template-columns: 1fr;">
			<div class="section-card">
				<div class="crack-header">
					<div>
						<h2 class="section-title">🔓 {$tr('wifiScanner.crackDiscovery')}</h2>
						<p class="section-desc">{$tr('wifiScanner.crackDesc')}</p>
					</div>
					<div class="crack-actions">
						<button class="btn-primary" onclick={startCrackDiscovery} disabled={cracking || !result || result.networks.length === 0}>
							{#if cracking}<span class="spinner"></span>{$tr('wifiScanner.analyzing')}{:else}🔓 {$tr('wifiScanner.startCrackAnalysis')}{/if}
						</button>
						<button class="btn-danger" onclick={startAutoCrack} disabled={autoCracking || !result || result.networks.length === 0}>
							{#if autoCracking}<span class="spinner"></span>{$tr('wifiScanner.autoCracking')}{:else}⚡ {$tr('wifiScanner.oneClickCrack')}{/if}
						</button>
					</div>
				</div>

				{#if autoCrackError}
					<div class="error-card" style="margin-bottom: 1rem;">
						<span class="error-icon">⚠️</span>
						<span class="error-text">{autoCrackError}</span>
					</div>
				{/if}

				{#if showAutoCrackResult && autoCrackResults.length > 0}
					<div class="auto-crack-section">
						<h3 class="subsection-title">⚡ {$tr('wifiScanner.oneClickCrackResult')}</h3>
						<div class="crack-summary" style="margin-bottom: 0.75rem;">
							<span class="crack-stat danger">🔓 {$tr('wifiScanner.crackable')}: {autoCrackResults.filter(r => r.crackable).length}</span>
							<span class="crack-stat success">✅ {$tr('wifiScanner.cracked')}: {autoCrackResults.filter(r => r.cracked).length}</span>
							<span class="crack-stat safe">🔒 {$tr('wifiScanner.secure')}: {autoCrackResults.filter(r => !r.crackable).length}</span>
						</div>
						<div class="auto-crack-list">
							{#each autoCrackResults as acr}
								<div class="auto-crack-card {acr.cracked ? 'cracked' : acr.crackable ? 'crackable' : 'secure'}">
									<div class="acr-header">
										<span class="acr-ssid">{acr.ssid}</span>
										<span class="encryption-badge" style="color: {getEncryptionColor(acr.encryption)}; border-color: {getEncryptionColor(acr.encryption)}40; background: {getEncryptionColor(acr.encryption)}15">{acr.encryption}</span>
										{#if acr.cracked}
											<span class="acr-badge cracked">✅ {$tr('wifiScanner.cracked')}</span>
										{:else if acr.crackable}
											<span class="acr-badge crackable">⚠️ {$tr('wifiScanner.crackable')}</span>
										{:else}
											<span class="acr-badge secure">🔒 {$tr('wifiScanner.secure')}</span>
										{/if}
									</div>
									<div class="acr-body">
										<div class="acr-detail"><span class="detail-label">{$tr('wifiScanner.crackMethod')}</span><span class="detail-value">{acr.method}</span></div>
										<div class="acr-detail"><span class="detail-label">{$tr('wifiScanner.estimatedTime')}</span><span class="detail-value">{acr.time_taken}</span></div>
										{#if acr.cracked && acr.password}
											<div class="acr-detail password-found">
												<span class="detail-label">🔑 {$tr('wifiScanner.foundPassword')}</span>
												<span class="detail-value mono password-value">{acr.password}</span>
											</div>
										{/if}
										<div class="acr-detail"><span class="detail-label">📝</span><span class="detail-value acr-details">{acr.details}</span></div>
									</div>
									{#if acr.cracked || acr.encryption === 'Open'}
										<div class="acr-footer">
											<button class="btn-small btn-connect" onclick={() => autoCrackAndConnect(acr)}>🔗 {$tr('wifiScanner.autoConnectBtn')}</button>
										</div>
									{/if}
								</div>
							{/each}
						</div>
					</div>
					<hr class="section-divider" />
				{/if}

				{#if !result || result.networks.length === 0}
					<div class="empty-state">
						<div class="empty-icon">🔍</div>
						<p>{$tr('wifiScanner.scanFirst')}</p>
					</div>
				{:else if crackError}
					<div class="error-card">
						<span class="error-icon">⚠️</span>
						<span class="error-text">{crackError}</span>
					</div>
				{:else if crackResults.length > 0}
					<div class="crack-results">
						<div class="crack-summary">
							<span class="crack-stat danger">🔓 {$tr('wifiScanner.crackable')}: {crackResults.filter(r => r.crackable).length}</span>
							<span class="crack-stat safe">🔒 {$tr('wifiScanner.secure')}: {crackResults.filter(r => !r.crackable).length}</span>
						</div>
						<table class="data-table">
							<thead>
								<tr>
									<th>{$tr('wifiScanner.ssid')}</th>
									<th>{$tr('wifiScanner.encryption')}</th>
									<th>{$tr('wifiScanner.crackable')}</th>
									<th>{$tr('wifiScanner.crackMethod')}</th>
									<th>{$tr('wifiScanner.estimatedTime')}</th>
									<th>{$tr('wifiScanner.confidence')}</th>
									<th>{$tr('wifiScanner.actions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each crackResults as cr}
									<tr class="{cr.crackable ? 'row-danger' : 'row-safe'}">
										<td class="mono">{cr.ssid}</td>
										<td>
											<span class="encryption-badge" style="color: {getEncryptionColor(cr.encryption)}; border-color: {getEncryptionColor(cr.encryption)}40; background: {getEncryptionColor(cr.encryption)}15">{cr.encryption}</span>
										</td>
										<td>
											{#if cr.crackable}
												<span class="crack-badge danger">⚠️ {$tr('wifiScanner.yes')}</span>
											{:else}
												<span class="crack-badge safe">✅ {$tr('wifiScanner.no')}</span>
											{/if}
										</td>
										<td>{cr.crack_method || '-'}</td>
										<td>{cr.crack_time_estimate || '-'}</td>
										<td>
											<div class="confidence-bar">
												<div class="confidence-fill" style="width: {cr.confidence * 100}%; background: {getCrackConfidenceColor(cr.confidence)}"></div>
												<span class="confidence-text">{(cr.confidence * 100).toFixed(0)}%</span>
											</div>
										</td>
										<td>
											<button class="btn-small btn-info" onclick={() => { selectedCrackNetwork = cr; showCrackDetail = true; }}>👁️</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else if !cracking}
					<div class="empty-state">
						<div class="empty-icon">🔓</div>
						<p>{$tr('wifiScanner.clickToAnalyze')}</p>
					</div>
				{/if}
			</div>
		</div>

		{#if showCrackDetail && selectedCrackNetwork}
			<div class="modal-overlay" onclick={() => showCrackDetail = false} onkeydown={(e) => e.key === 'Escape' && (showCrackDetail = false)}>
				<div class="modal-content" style="max-width: 550px;" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
					<div class="modal-header">
						<h2>🔓 {$tr('wifiScanner.crackDetail')}</h2>
						<button class="modal-close" onclick={() => showCrackDetail = false}>✕</button>
					</div>
					<div class="modal-body">
						<div class="detail-section">
							<h4>{$tr('wifiScanner.basicInfo')}</h4>
							<div class="detail-grid">
								<div class="detail-item">
									<span class="detail-label">SSID</span>
									<span class="detail-value mono">{selectedCrackNetwork.ssid}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">BSSID</span>
									<span class="detail-value mono">{selectedCrackNetwork.bssid}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.encryption')}</span>
									<span class="detail-value" style="color: {getEncryptionColor(selectedCrackNetwork.encryption)}">{selectedCrackNetwork.encryption}</span>
								</div>
								<div class="detail-item">
									<span class="detail-label">{$tr('wifiScanner.crackable')}</span>
									<span class="detail-value" style="color: {selectedCrackNetwork.crackable ? '#ef4444' : '#22c55e'}">{selectedCrackNetwork.crackable ? $tr('wifiScanner.yes') : $tr('wifiScanner.no')}</span>
								</div>
							</div>
						</div>
						{#if selectedCrackNetwork.crackable}
							<div class="detail-section">
								<h4>🔓 {$tr('wifiScanner.crackAnalysis')}</h4>
								<div class="detail-grid">
									<div class="detail-item" style="grid-column: 1 / -1;">
										<span class="detail-label">{$tr('wifiScanner.crackMethod')}</span>
										<span class="detail-value">{selectedCrackNetwork.crack_method}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('wifiScanner.estimatedTime')}</span>
										<span class="detail-value">{selectedCrackNetwork.crack_time_estimate}</span>
									</div>
									<div class="detail-item">
										<span class="detail-label">{$tr('wifiScanner.confidence')}</span>
										<span class="detail-value" style="color: {getCrackConfidenceColor(selectedCrackNetwork.confidence)}">{(selectedCrackNetwork.confidence * 100).toFixed(0)}%</span>
									</div>
								</div>
							</div>
						{/if}
						{#if selectedCrackNetwork.details}
							<div class="detail-section">
								<h4>📝 {$tr('wifiScanner.analysisDetails')}</h4>
								<div class="detail-summary">{selectedCrackNetwork.details}</div>
							</div>
						{/if}
					</div>
					<div class="modal-footer">
						<button class="btn-secondary" onclick={() => showCrackDetail = false}>{$tr('wifiScanner.close')}</button>
					</div>
				</div>
			</div>
		{/if}

	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="wifi_scanner" toolName={$tr('wifiScanner.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="wifi_scanner" />
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
		grid-template-columns: 320px 1fr;
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
		margin: 0 0 1rem;
	}

	.section-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0;
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

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		font-size: 0.825rem;
		color: #cbd5e1;
	}

	.checkbox-label input[type="checkbox"] {
		accent-color: #a855f7;
		width: 0.9rem;
		height: 0.9rem;
	}

	.button-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 1rem;
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
		box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

	.btn-secondary {
		padding: 0.65rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) { border-color: #a855f7; color: #a855f7; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-small {
		padding: 0.25rem 0.5rem;
		border-radius: 0.375rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-info:hover { border-color: #3b82f6; background: rgba(59, 130, 246, 0.1); }
	.btn-connect:hover { border-color: #22c55e; background: rgba(34, 197, 94, 0.1); }

	.spinner {
		display: inline-block;
		width: 0.9rem;
		height: 0.9rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.risk-indicator {
		text-align: center;
		padding: 0.75rem;
		border: 2px solid;
		border-radius: 0.5rem;
		margin-bottom: 1rem;
		background: rgba(15, 23, 42, 0.5);
	}

	.risk-label {
		font-size: 0.7rem;
		color: #94a3b8;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		margin-bottom: 0.25rem;
	}

	.risk-value {
		font-size: 1.5rem;
		font-weight: 700;
	}

	.security-stats {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.375rem;
	}

	.stat-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.35rem 0.6rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
		font-size: 0.75rem;
	}

	.stat-label { color: #94a3b8; }
	.stat-value { font-weight: 600; color: #d1d5db; }
	.stat-item.danger .stat-value { color: #ef4444; }
	.stat-item.warning .stat-value { color: #f97316; }
	.stat-item.info .stat-value { color: #3b82f6; }
	.stat-item.safe .stat-value { color: #22c55e; }

	.result-summary {
		padding: 0.75rem 1rem;
		border-radius: 0.5rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
		background: rgba(168, 85, 247, 0.08);
		border: 1px solid rgba(168, 85, 247, 0.15);
		color: #c4b5fd;
		line-height: 1.5;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.5rem;
		padding: 0.2rem;
	}

	.result-tab {
		flex: 1;
		padding: 0.45rem 0.75rem;
		border: none;
		border-radius: 0.375rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.8rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) { background: rgba(168, 85, 247, 0.08); }

	.network-table-wrapper {
		overflow-x: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.1);
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

	.data-table tr:hover { background: rgba(168, 85, 247, 0.05); }

	.ssid-cell { display: flex; align-items: center; gap: 0.4rem; }
	.ssid-name { font-weight: 600; color: #f1f5f9; }

	.hidden-badge {
		font-size: 0.6rem;
		padding: 0.1rem 0.35rem;
		border-radius: 9999px;
		background: rgba(234, 179, 8, 0.15);
		color: #eab308;
		border: 1px solid rgba(234, 179, 8, 0.3);
	}

	.signal-cell { display: flex; flex-direction: column; gap: 0.1rem; }
	.signal-bars { font-size: 0.7rem; letter-spacing: 1px; }
	.signal-bars[data-level="excellent"] { color: #22c55e; }
	.signal-bars[data-level="good"] { color: #3b82f6; }
	.signal-bars[data-level="fair"] { color: #eab308; }
	.signal-bars[data-level="weak"] { color: #ef4444; }
	.signal-db { font-size: 0.7rem; color: #94a3b8; }

	.mono {
		font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
		font-size: 0.8rem;
		color: #60a5fa;
	}

	.encryption-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.7rem;
		font-weight: 600;
		border: 1px solid;
		display: inline-block;
	}

	.score-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.7rem;
		font-weight: 700;
		border: 1px solid;
		display: inline-block;
		min-width: 2.5rem;
		text-align: center;
	}

	.actions-cell { white-space: nowrap; }
	.actions-cell .btn-small { margin-right: 0.25rem; }

	.vuln-list {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.vuln-card {
		padding: 0.875rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-left: 3px solid;
		border-radius: 0.5rem;
	}

	.vuln-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
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

	.vuln-category {
		font-size: 0.8rem;
		font-weight: 600;
		color: #f1f5f9;
	}

	.vuln-desc {
		font-size: 0.85rem;
		color: #d1d5db;
		margin: 0 0 0.5rem;
		line-height: 1.5;
	}

	.vuln-footer {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.vuln-affected {
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.vuln-rec {
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1rem;
		color: #94a3b8;
	}

	.empty-state p { margin: 0; font-size: 0.9rem; }
	.empty-state.safe p { color: #22c55e; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }

	.error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
	}

	.error-icon { font-size: 1.2rem; }
	.error-text { color: #ef4444; font-size: 0.85rem; }

	.crack-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 1.25rem;
	}

	.crack-header .btn-primary { flex: unset; padding: 0.5rem 1rem; font-size: 0.85rem; }

	.crack-results { margin-top: 1rem; }

	.crack-summary {
		display: flex;
		gap: 1.5rem;
		margin-bottom: 1rem;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.crack-stat {
		font-size: 0.85rem;
		font-weight: 600;
	}

	.crack-stat.danger { color: #ef4444; }
	.crack-stat.safe { color: #22c55e; }

	.crack-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.7rem;
		font-weight: 600;
		display: inline-block;
	}

	.crack-badge.danger {
		background: rgba(239, 68, 68, 0.15);
		color: #ef4444;
		border: 1px solid rgba(239, 68, 68, 0.3);
	}

	.crack-badge.safe {
		background: rgba(34, 197, 94, 0.15);
		color: #22c55e;
		border: 1px solid rgba(34, 197, 94, 0.3);
	}

	.row-danger { background: rgba(239, 68, 68, 0.03); }
	.row-safe { background: rgba(34, 197, 94, 0.03); }

	.confidence-bar {
		position: relative;
		width: 100%;
		height: 1.25rem;
		background: rgba(15, 23, 42, 0.8);
		border-radius: 0.25rem;
		overflow: hidden;
	}

	.confidence-fill {
		height: 100%;
		border-radius: 0.25rem;
		transition: width 0.3s;
	}

	.confidence-text {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		font-size: 0.65rem;
		font-weight: 600;
		color: #f1f5f9;
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

	.modal-body { padding: 1.5rem; }

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

	.detail-section:last-child { margin-bottom: 0; }

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
		color: #f1f5f9;
		font-weight: 500;
	}

	.notes-list {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.note-item {
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
		font-size: 0.825rem;
		color: #cbd5e1;
		line-height: 1.5;
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

	.connect-success {
		text-align: center;
		padding: 2rem 1rem;
	}

	.success-icon { font-size: 3rem; margin-bottom: 0.75rem; }

	.connect-success p {
		color: #22c55e;
		font-size: 1rem;
		font-weight: 600;
		margin: 0;
	}

	.connect-info {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.connect-detail {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
	}

	@media (max-width: 768px) {
		.nd-page { padding: 1rem; }
		.content-grid { grid-template-columns: 1fr; }
		.detail-grid { grid-template-columns: 1fr; }
		.page-header { flex-direction: column; align-items: flex-start; gap: 0.75rem; }
		.tabs { overflow-x: auto; }
		.crack-header { flex-direction: column; gap: 0.75rem; }
		.crack-actions { flex-direction: column; }
		.filter-bar { flex-wrap: wrap; }
	}

	.form-group { position: relative; }

	.btn-refresh {
		position: absolute;
		right: 0.5rem;
		top: 1.6rem;
		background: rgba(168, 85, 247, 0.15);
		border: 1px solid rgba(168, 85, 247, 0.3);
		color: #a855f7;
		width: 1.8rem;
		height: 1.8rem;
		border-radius: 0.375rem;
		cursor: pointer;
		font-size: 0.75rem;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all 0.2s;
		padding: 0;
	}

	.btn-refresh:hover:not(:disabled) { background: rgba(168, 85, 247, 0.25); border-color: rgba(168, 85, 247, 0.5); }
	.btn-refresh:disabled { opacity: 0.5; cursor: not-allowed; }

	select.form-input {
		appearance: none;
		padding-right: 2.5rem;
		cursor: pointer;
		background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2394a3b8' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
		background-repeat: no-repeat;
		background-position: right 0.75rem center;
	}

	.filter-bar {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.75rem;
		background: rgba(15, 23, 42, 0.6);
		border-radius: 0.5rem;
		padding: 0.2rem;
		overflow-x: auto;
	}

	.filter-btn {
		padding: 0.35rem 0.65rem;
		border: none;
		border-radius: 0.375rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.filter-btn.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c4b5fd;
		font-weight: 600;
	}

	.filter-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.08); }

	.crack-actions {
		display: flex;
		gap: 0.5rem;
		align-items: flex-start;
	}

	.btn-danger {
		background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
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

	.btn-danger:hover:not(:disabled) {
		box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
		transform: translateY(-1px);
	}

	.btn-danger:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

	.auto-crack-section { margin-bottom: 1rem; }

	.subsection-title {
		font-size: 1rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 0.75rem;
	}

	.crack-stat.success { color: #22c55e; }

	.auto-crack-list {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.auto-crack-card {
		padding: 0.875rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-left: 3px solid;
		border-radius: 0.5rem;
	}

	.auto-crack-card.cracked { border-left-color: #22c55e; background: rgba(34, 197, 94, 0.03); }
	.auto-crack-card.crackable { border-left-color: #f97316; background: rgba(249, 115, 22, 0.03); }
	.auto-crack-card.secure { border-left-color: #3b82f6; background: rgba(59, 130, 246, 0.03); }

	.acr-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.625rem;
		flex-wrap: wrap;
	}

	.acr-ssid {
		font-weight: 600;
		color: #f1f5f9;
		font-size: 0.9rem;
	}

	.acr-badge {
		padding: 0.15rem 0.5rem;
		border-radius: 0.375rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.acr-badge.cracked { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }
	.acr-badge.crackable { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
	.acr-badge.secure { background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }

	.acr-body {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.acr-detail {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.4rem 0.65rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.375rem;
		font-size: 0.8rem;
		gap: 0.5rem;
	}

	.acr-detail.password-found {
		background: rgba(34, 197, 94, 0.08);
		border-color: rgba(34, 197, 94, 0.2);
	}

	.password-value {
		color: #22c55e !important;
		font-weight: 700;
		font-size: 0.9rem !important;
		letter-spacing: 0.05em;
	}

	.acr-details {
		font-size: 0.75rem;
		color: #94a3b8;
		line-height: 1.5;
		text-align: right;
		max-width: 70%;
	}

	.acr-footer {
		margin-top: 0.5rem;
		display: flex;
		justify-content: flex-end;
	}

	.section-divider {
		border: none;
		border-top: 1px solid rgba(168, 85, 247, 0.15);
		margin: 1.25rem 0;
	}

	.demo-notice {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.6rem 1rem;
		background: rgba(234, 179, 8, 0.08);
		border: 1px solid rgba(234, 179, 8, 0.25);
		border-radius: 0.5rem;
		margin-bottom: 0.75rem;
		font-size: 0.8rem;
	}

	.demo-icon { font-size: 1rem; }

	.demo-text {
		color: #eab308;
		line-height: 1.4;
	}
</style>
