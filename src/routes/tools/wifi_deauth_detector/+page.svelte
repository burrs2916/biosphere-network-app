<script lang="ts">
	import { tr } from '$lib/i18n';
	import { onMount } from 'svelte';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface NetworkInterfaceInfo {
		name: string;
		display_name: string;
		is_wifi: boolean;
		is_up: boolean;
		mac_address: string;
		ip_address: string | null;
	}

	interface DeauthPacket {
		timestamp: string;
		source_mac: string;
		destination_mac: string;
		bssid: string;
		channel: number;
		signal_dbm: number;
		packet_type: string;
		reason_code: number;
		reason_description: string;
		is_suspicious: boolean;
	}

	interface AccessPoint {
		ssid: string;
		bssid: string;
		channel: number;
		signal_dbm: number;
		encryption: string;
		is_suspicious: boolean;
		deauth_count: number;
		clients_affected: string[];
	}

	interface DeauthAlert {
		severity: string;
		alert_type: string;
		description: string;
		source_mac: string;
		target_mac: string;
		bssid: string;
		channel: number;
		packet_count: number;
		recommendation: string;
		timestamp: string;
	}

	interface ChannelAnalysis {
		channel: number;
		total_packets: number;
		deauth_packets: number;
		deauth_ratio: number;
		is_anomalous: boolean;
		access_points: string[];
	}

	interface WifiDeauthFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface WifiDeauthResult {
		success: boolean;
		interface: string;
		scan_duration: number;
		total_packets_captured: number;
		deauth_packets_detected: number;
		access_points: AccessPoint[];
		deauth_packets: DeauthPacket[];
		alerts: DeauthAlert[];
		channel_analysis: ChannelAnalysis[];
		attack_detected: boolean;
		attack_type: string;
		security_findings: WifiDeauthFinding[];
		summary: string;
	}

	let interface_ = $state('');
	let interfaces = $state<NetworkInterfaceInfo[]>([]);
	let interfacesLoaded = $state(false);
	let scanDuration = $state(30);
	let alertThreshold = $state(5);
	let detectAllChannels = $state(true);
	let channel = $state<number | null>(null);
	let capturePackets = $state(true);
	let monitorMode = $state(true);
	let result = $state<WifiDeauthResult | null>(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('detect');
	let activeResultTab = $state('overview');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let historyComponent = $state<ToolHistory>();
	let scanProgress = $state('');
	let scanStartTime = $state(0);

	onMount(() => {
		loadInterfaces();
	});

	async function loadInterfaces() {
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			interfaces = await invoke<NetworkInterfaceInfo[]>('list_wifi_interfaces_command');
			interfacesLoaded = true;
			if (interface_ === '' && interfaces.length > 0) {
				const wifiIf = interfaces.find((i: NetworkInterfaceInfo) => i.is_wifi);
				if (wifiIf) {
					interface_ = wifiIf.name;
				} else if (interfaces.length > 0) {
					interface_ = interfaces[0].name;
				}
			}
		} catch (_e) {
			interfacesLoaded = true;
			if (interface_ === '') interface_ = 'en0';
		}
	}

	let securityScore = $derived(calcSecurityScore());
	let criticalAlerts = $derived(result ? result.alerts.filter((a: DeauthAlert) => a.severity === 'critical').length : 0);
	let highAlerts = $derived(result ? result.alerts.filter((a: DeauthAlert) => a.severity === 'high').length : 0);
	let mediumAlerts = $derived(result ? result.alerts.filter((a: DeauthAlert) => a.severity === 'medium').length : 0);
	let lowAlerts = $derived(result ? result.alerts.filter((a: DeauthAlert) => a.severity === 'low').length : 0);

	function calcSecurityScore(): { score: number; level: string } {
		if (!result) return { score: -1, level: '' };
		let score = 100;
		if (result.attack_detected) score -= 30;
		score -= criticalAlerts * 15;
		score -= highAlerts * 10;
		score -= mediumAlerts * 5;
		score -= lowAlerts * 2;
		const openNets = result.access_points.filter((ap: AccessPoint) => ap.encryption === 'OPN' || ap.encryption === 'Open').length;
		score -= openNets * 5;
		const wepNets = result.access_points.filter((ap: AccessPoint) => ap.encryption.includes('WEP')).length;
		score -= wepNets * 10;
		score = Math.max(0, Math.min(100, score));
		let level = '';
		if (score >= 80) level = 'good';
		else if (score >= 60) level = 'warning';
		else if (score >= 40) level = 'danger';
		else level = 'critical';
		return { score, level };
	}

	async function startDetection() {
		processing = true; error = ''; result = null;
		scanStartTime = Date.now();
		scanProgress = $tr('wifiDeauthDetector.detecting');
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			scanProgress = $tr('wifiDeauthDetector.detecting') + '...';
			result = await invoke<WifiDeauthResult>('wifi_deauth_detect_command', {
				config: {
					interface: interface_.trim(),
					scan_duration: scanDuration,
					channel: detectAllChannels ? null : channel,
					detect_all_channels: detectAllChannels,
					alert_threshold: alertThreshold,
					monitor_mode: monitorMode,
					capture_packets: capturePackets,
					max_packets: 1000,
					timeout: 120,
				}
			});
			scanProgress = '';
			if (historyComponent) {
				historyComponent.saveHistory(
					`${interface_} ${scanDuration}s`,
					JSON.stringify(result),
					result.summary,
					result.attack_detected ? 'warning' : 'success'
				);
			}
		} catch (e: any) {
			error = e.toString();
			scanProgress = '';
			if (historyComponent) {
				historyComponent.saveHistory(
					`${interface_} ${scanDuration}s`,
					JSON.stringify({ error: e.toString() }),
					undefined,
					'failed'
				);
			}
		} finally {
			processing = false;
		}
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const { writeFile } = await import('@tauri-apps/plugin-fs');
			const path = await save({
				defaultPath: `wifi-deauth-${Date.now()}.${exportFormat}`,
				filters: [{ name: exportFormat.toUpperCase(), extensions: [exportFormat] }]
			});
			if (path) {
				const content = exportFormat === 'json'
					? JSON.stringify(result, null, 2)
					: convertToCsv(result);
				const encoder = new TextEncoder();
				await writeFile(path, encoder.encode(content));
			}
		} catch (e) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function convertToCsv(data: WifiDeauthResult): string {
		const rows: string[][] = [['Category', 'Severity', 'Description', 'Recommendation']];
		for (const f of data.security_findings) {
			rows.push([f.category, f.severity, f.description, f.recommendation]);
		}
		for (const a of data.alerts) {
			rows.push([a.alert_type, a.severity, a.description, a.recommendation]);
		}
		return rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
	}

	function getScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#eab308';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function getScoreLabel(level: string): string {
		switch (level) {
			case 'good': return $tr('wifiDeauthDetector.scoreSecure');
			case 'warning': return $tr('wifiDeauthDetector.scoreWarning');
			case 'danger': return $tr('wifiDeauthDetector.scoreDanger');
			case 'critical': return $tr('wifiDeauthDetector.scoreCritical');
			default: return '';
		}
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#ef4444';
			case 'high': return '#f97316';
			case 'medium': return '#eab308';
			case 'low': return '#3b82f6';
			default: return '#94a3b8';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.1)';
			case 'high': return 'rgba(249, 115, 22, 0.1)';
			case 'medium': return 'rgba(234, 179, 8, 0.1)';
			case 'low': return 'rgba(59, 130, 246, 0.1)';
			default: return 'rgba(148, 163, 184, 0.1)';
		}
	}

	function getSeverityBorder(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.3)';
			case 'high': return 'rgba(249, 115, 22, 0.3)';
			case 'medium': return 'rgba(234, 179, 8, 0.3)';
			case 'low': return 'rgba(59, 130, 246, 0.3)';
			default: return 'rgba(148, 163, 184, 0.3)';
		}
	}

	function getEncryptionClass(encryption: string): string {
		if (encryption === 'WPA3') return 'tag-success';
		if (encryption === 'WPA2') return 'tag-cyan';
		if (encryption.includes('WEP')) return 'tag-danger';
		if (encryption === 'OPN' || encryption === 'Open') return 'tag-warning';
		return '';
	}

	function formatTime(ts: string): string {
		try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<a href="/tools" class="back-link">{$tr('common.backToTools')}</a>
		<h1 class="page-title">📡 {$tr('wifiDeauthDetector.title')}</h1>
		<p class="page-subtitle">{$tr('wifiDeauthDetector.subtitle')}</p>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'detect' ? 'active' : ''}" onclick={() => (activeMainTab = 'detect')}>
			<span class="tab-icon">🔍</span> {$tr('wifiDeauthDetector.detect')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => (activeMainTab = 'history')}>
			<span class="tab-icon">📋</span> {$tr('common.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => (activeMainTab = 'help')}>
			<span class="tab-icon">📖</span> {$tr('common.help')}
		</button>
	</div>

	{#if activeMainTab === 'detect'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">🔍 {$tr('wifiDeauthDetector.configTitle')}</h2>
					<p class="section-desc">{$tr('wifiDeauthDetector.configDesc')}</p>

					<div class="form-group">
						<label class="form-label" for="wd-interface">{$tr('wifiDeauthDetector.interface')}</label>
						{#if interfaces.length > 0}
							<select id="wd-interface" bind:value={interface_} class="form-input" disabled={processing}>
								{#each interfaces as iface}
									<option value={iface.name}>
										{iface.name} {iface.is_wifi ? '📡' : '🔌'} {iface.is_up ? '✅' : '⏸'} {iface.ip_address ? `(${iface.ip_address})` : ''}
									</option>
								{/each}
							</select>
						{:else}
							<input id="wd-interface" type="text" bind:value={interface_} placeholder="en0" class="form-input" disabled={processing} />
						{/if}
						{#if !interfacesLoaded}
							<span class="loading-hint">⏳ {$tr('wifiDeauthDetector.detecting')}</span>
						{/if}
					</div>

					<div class="form-group">
						<label class="form-label" for="wd-duration">{$tr('wifiDeauthDetector.scanDuration')} (s)</label>
						<input id="wd-duration" type="number" bind:value={scanDuration} min="5" max="300" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label" for="wd-threshold">{$tr('wifiDeauthDetector.alertThreshold')}</label>
						<input id="wd-threshold" type="number" bind:value={alertThreshold} min="1" max="100" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<span class="form-label">{$tr('wifiDeauthDetector.scanOptions')}</span>
						<div class="target-grid">
							<label class="target-chip {detectAllChannels ? 'active' : ''}">
								<input type="checkbox" bind:checked={detectAllChannels} disabled={processing} />
								<span>📡 {$tr('wifiDeauthDetector.allChannels')}</span>
							</label>
							<label class="target-chip {capturePackets ? 'active' : ''}">
								<input type="checkbox" bind:checked={capturePackets} disabled={processing} />
								<span>📦 {$tr('wifiDeauthDetector.capturePackets')}</span>
							</label>
							<label class="target-chip {monitorMode ? 'active' : ''}">
								<input type="checkbox" bind:checked={monitorMode} disabled={processing} />
								<span>👁️ {$tr('wifiDeauthDetector.monitorMode')}</span>
							</label>
						</div>
					</div>

					{#if !detectAllChannels}
						<div class="form-group">
							<label class="form-label" for="wd-channel">{$tr('wifiDeauthDetector.specificChannel')}</label>
							<input id="wd-channel" type="number" bind:value={channel} min="1" max="165" placeholder="6" class="form-input" disabled={processing} />
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" onclick={startDetection} disabled={processing || !interface_.trim()}>
							{#if processing}
								<span class="spinner"></span> {scanProgress || $tr('wifiDeauthDetector.detecting')}
							{:else}
								📡 {$tr('wifiDeauthDetector.startDetection')}
							{/if}
						</button>
						<button class="btn-secondary" onclick={() => { interface_ = ''; result = null; error = ''; }} disabled={processing}>
							🗑️ {$tr('common.clear')}
						</button>
					</div>

					{#if processing}
						<div class="progress-section">
							<div class="progress-bar-track">
								<div class="progress-bar-fill" style="width: {Math.min(((Date.now() - scanStartTime) / (scanDuration * 1000)) * 100, 95)}%"></div>
							</div>
							<div class="progress-text">
								{scanProgress} ({Math.round((Date.now() - scanStartTime) / 1000)}s / {scanDuration}s)
							</div>
						</div>
					{/if}
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="error-banner">
						<span class="error-icon">❌</span>
						<span>{error}</span>
					</div>
				{/if}

				{#if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {getScoreColor(securityScore.score)}; color: {getScoreColor(securityScore.score)};">
								<span class="score-number">{securityScore.score}</span>
								<span class="score-label">{getScoreLabel(securityScore.level)}</span>
							</div>
							<div class="score-details">
								<h3 class="section-title" style="margin-bottom:0.5rem">{$tr('wifiDeauthDetector.result.title')}</h3>
								<p class="result-summary">{result.summary}</p>
								<div class="score-badges">
									{#if result.attack_detected}
										<span class="badge badge-danger">⚠️ {$tr('wifiDeauthDetector.attackDetected')}</span>
									{:else}
										<span class="badge badge-success">✅ {$tr('wifiDeauthDetector.noAttack')}</span>
									{/if}
									{#if criticalAlerts > 0}<span class="badge badge-danger">🔴 {criticalAlerts} {$tr('wifiDeauthDetector.critical')}</span>{/if}
									{#if highAlerts > 0}<span class="badge badge-warning">🟠 {highAlerts} {$tr('wifiDeauthDetector.highRisk')}</span>{/if}
									{#if mediumAlerts > 0}<span class="badge badge-info">🟡 {mediumAlerts} {$tr('wifiDeauthDetector.mediumRisk')}</span>{/if}
								</div>
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

					<div class="section-card stats-section">
						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value" style="color: #a855f7;">{result.access_points.length}</div>
								<div class="stat-label">{$tr('wifiDeauthDetector.result.accessPoints')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #6366f1;">{result.total_packets_captured}</div>
								<div class="stat-label">{$tr('wifiDeauthDetector.result.packets')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: {result.deauth_packets_detected > 0 ? '#ef4444' : '#22c55e'};">{result.deauth_packets_detected}</div>
								<div class="stat-label">Deauth {$tr('wifiDeauthDetector.result.packets')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: {result.alerts.length > 0 ? '#f97316' : '#22c55e'};">{result.alerts.length}</div>
								<div class="stat-label">{$tr('wifiDeauthDetector.result.alerts')}</div>
							</div>
						</div>
					</div>

					{#if result.attack_detected}
						<div class="section-card alert-attack">
							<div class="attack-header">
								<span class="attack-icon">⚠️</span>
								<span class="attack-type">{$tr('wifiDeauthDetector.attackType')}: {result.attack_type}</span>
							</div>
						</div>
					{/if}

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => (activeResultTab = 'overview')}>📊 {$tr('wifiDeauthDetector.tabOverview')}</button>
							<button class="result-tab {activeResultTab === 'aps' ? 'active' : ''}" onclick={() => (activeResultTab = 'aps')}>📡 {$tr('wifiDeauthDetector.result.accessPoints')}</button>
							<button class="result-tab {activeResultTab === 'packets' ? 'active' : ''}" onclick={() => (activeResultTab = 'packets')}>📦 {$tr('wifiDeauthDetector.tabPackets')}</button>
							<button class="result-tab {activeResultTab === 'alerts' ? 'active' : ''}" onclick={() => (activeResultTab = 'alerts')}>🚨 {$tr('wifiDeauthDetector.result.alerts')}</button>
							<button class="result-tab {activeResultTab === 'channels' ? 'active' : ''}" onclick={() => (activeResultTab = 'channels')}>📊 {$tr('wifiDeauthDetector.result.channels')}</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => (activeResultTab = 'findings')}>🛡️ {$tr('wifiDeauthDetector.tabFindings')}</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="detail-grid">
								{#if result.alerts.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">🚨 {$tr('wifiDeauthDetector.recentAlerts')}</h3>
										<div class="findings-compact">
											{#each result.alerts.slice(0, 5) as alert}
												<div class="finding-compact">
													<span class="finding-dot" style="background:{getSeverityColor(alert.severity)};"></span>
													<span class="finding-cat">{alert.alert_type}</span>
													<span class="finding-sep">-</span>
													<span class="finding-desc">{alert.description}</span>
												</div>
											{/each}
											{#if result.alerts.length > 5}
												<div class="finding-more">+{result.alerts.length - 5} {$tr('wifiDeauthDetector.moreAlerts')}</div>
											{/if}
										</div>
									</div>
								{/if}

								{#if result.channel_analysis.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">📊 {$tr('wifiDeauthDetector.channelOverview')}</h3>
										<div class="channel-grid">
											{#each result.channel_analysis as ch}
												<div class="channel-chip {ch.is_anomalous ? 'channel-anomalous' : ''}">
													<div class="channel-num {ch.is_anomalous ? 'text-danger' : ''}">CH{ch.channel}</div>
													<div class="channel-info">{ch.deauth_packets} deauth</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.access_points.length > 0}
									<div class="detail-card">
										<h3 class="subsection-title">📡 {$tr('wifiDeauthDetector.apSummary')}</h3>
										<div class="mini-stats">
											<div class="mini-stat"><span class="mini-val" style="color:#06b6d4;">{result.access_points.length}</span><span class="mini-label">{$tr('wifiDeauthDetector.totalAPs')}</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#ef4444;">{result.access_points.filter((ap: AccessPoint) => ap.is_suspicious).length}</span><span class="mini-label">{$tr('wifiDeauthDetector.suspiciousAPs')}</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#eab308;">{result.access_points.filter((ap: AccessPoint) => ap.encryption === 'OPN' || ap.encryption === 'Open').length}</span><span class="mini-label">{$tr('wifiDeauthDetector.openNetworks')}</span></div>
											<div class="mini-stat"><span class="mini-val" style="color:#22c55e;">{result.access_points.filter((ap: AccessPoint) => ap.encryption === 'WPA3').length}</span><span class="mini-label">WPA3</span></div>
										</div>
									</div>
								{/if}

								{#if result.deauth_packets.length > 0}
									<div class="detail-card" style="grid-column: 1 / -1;">
										<h3 class="subsection-title">⏱️ Attack Timeline</h3>
										<div class="timeline">
											{#each result.deauth_packets.slice(0, 10) as pkt, i}
												<div class="timeline-item {pkt.is_suspicious ? 'timeline-danger' : 'timeline-normal'}">
													<div class="timeline-dot" style="background: {pkt.is_suspicious ? '#ef4444' : '#22c55e'};"></div>
													<div class="timeline-content">
														<div class="timeline-header">
															<span class="timeline-time">{formatTime(pkt.timestamp)}</span>
															<span class="timeline-type">{pkt.packet_type}</span>
															{#if pkt.is_suspicious}<span class="badge badge-danger">⚠️</span>{/if}
														</div>
														<div class="timeline-detail">
															<span class="mono-small">{pkt.source_mac}</span> → <span class="mono-small">{pkt.destination_mac}</span>
															<span class="text-xs text-muted">CH{pkt.channel} {pkt.signal_dbm}dBm RC:{pkt.reason_code}</span>
														</div>
													</div>
												</div>
											{/each}
											{#if result.deauth_packets.length > 10}
												<div class="timeline-more">+{result.deauth_packets.length - 10} more packets</div>
											{/if}
										</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'aps'}
							<div class="detail-card">
								<h3 class="subsection-title">📡 {$tr('wifiDeauthDetector.result.accessPoints')} ({result.access_points.length})</h3>
								{#if result.access_points.length > 0}
									<div class="table-wrap">
										<table class="data-table">
											<thead>
												<tr>
													<th>SSID</th>
													<th>BSSID</th>
													<th>{$tr('wifiDeauthDetector.channel')}</th>
													<th>{$tr('wifiDeauthDetector.signal')}</th>
													<th>{$tr('wifiDeauthDetector.encryption')}</th>
													<th>Deauth</th>
													<th>{$tr('wifiDeauthDetector.status')}</th>
												</tr>
											</thead>
											<tbody>
												{#each result.access_points as ap}
													<tr class:row-danger={ap.is_suspicious}>
														<td class="mono-blue">{ap.ssid}</td>
														<td class="mono-small">{ap.bssid}</td>
														<td class="text-center">{ap.channel}</td>
														<td class="text-center">{ap.signal_dbm}dBm</td>
														<td class="text-center"><span class="tag {getEncryptionClass(ap.encryption)}">{ap.encryption}</span></td>
														<td class="text-center {ap.deauth_count > 0 ? 'text-danger font-bold' : 'text-muted'}">{ap.deauth_count}</td>
														<td class="text-center">
															{#if ap.is_suspicious}
																<span class="text-danger">⚠️</span>
															{:else}
																<span class="text-success">✅</span>
															{/if}
														</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{:else}
									<p class="empty-text">{$tr('wifiDeauthDetector.noAPs')}</p>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'packets'}
							<div class="detail-card">
								<h3 class="subsection-title">📦 Deauth {$tr('wifiDeauthDetector.tabPackets')} ({result.deauth_packets.length})</h3>
								{#if result.deauth_packets.length > 0}
									<div class="table-wrap">
										<table class="data-table">
											<thead>
												<tr>
													<th>{$tr('wifiDeauthDetector.time')}</th>
													<th>{$tr('wifiDeauthDetector.sourceMac')}</th>
													<th>{$tr('wifiDeauthDetector.destMac')}</th>
													<th>BSSID</th>
													<th>{$tr('wifiDeauthDetector.type')}</th>
													<th>{$tr('wifiDeauthDetector.reason')}</th>
													<th>{$tr('wifiDeauthDetector.suspicious')}</th>
												</tr>
											</thead>
											<tbody>
												{#each result.deauth_packets.slice(0, 100) as pkt}
													<tr class:row-danger={pkt.is_suspicious}>
														<td class="text-xs">{formatTime(pkt.timestamp)}</td>
														<td class="mono-small mono-blue">{pkt.source_mac}</td>
														<td class="mono-small mono-green">{pkt.destination_mac}</td>
														<td class="mono-small">{pkt.bssid}</td>
														<td class="text-xs">{pkt.packet_type}</td>
														<td class="text-xs" title={pkt.reason_description}>{pkt.reason_code} - {pkt.reason_description.length > 20 ? pkt.reason_description.slice(0, 20) + '...' : pkt.reason_description}</td>
														<td class="text-center">
															{#if pkt.is_suspicious}
																<span class="text-danger">⚠️</span>
															{:else}
																<span class="text-muted">-</span>
															{/if}
														</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{:else}
									<p class="empty-text">{$tr('wifiDeauthDetector.noPackets')}</p>
								{/if}
							</div>
						{/if}

						{#if activeResultTab === 'alerts'}
							{#if result.alerts.length > 0}
								<div class="detail-grid">
									{#each result.alerts as alert}
										<div class="detail-card" style="border-color: {getSeverityBorder(alert.severity)}; background: {getSeverityBg(alert.severity)};">
											<div class="finding-header">
												<span class="finding-dot" style="background:{getSeverityColor(alert.severity)};"></span>
												<span class="finding-cat">{alert.alert_type}</span>
												<span class="finding-severity" style="color:{getSeverityColor(alert.severity)};">{alert.severity.toUpperCase()}</span>
											</div>
											<p class="finding-desc">{alert.description}</p>
											<div class="alert-meta">
												<span>{$tr('wifiDeauthDetector.sourceMac')}: <span class="mono-blue">{alert.source_mac}</span></span>
												<span>{$tr('wifiDeauthDetector.destMac')}: <span class="mono-green">{alert.target_mac}</span></span>
												<span>BSSID: <span class="mono-small">{alert.bssid}</span></span>
												<span>{$tr('wifiDeauthDetector.channel')}: {alert.channel}</span>
												<span>{$tr('wifiDeauthDetector.packetCount')}: <span class="text-danger">{alert.packet_count}</span></span>
											</div>
											<p class="finding-recommendation">💡 {alert.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="alert-success-box">
									✅ {$tr('wifiDeauthDetector.noAlerts')}
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'channels'}
							{#if result.channel_analysis.length > 0}
								<div class="detail-grid">
									{#each result.channel_analysis as ch}
										<div class="detail-card" style="border-color: {ch.is_anomalous ? 'rgba(239,68,68,0.3)' : 'rgba(148,163,184,0.1)'};">
											<div class="channel-header">
												<span class="channel-title">{$tr('wifiDeauthDetector.channel')} {ch.channel}</span>
												{#if ch.is_anomalous}
													<span class="badge badge-danger">⚠️ {$tr('wifiDeauthDetector.anomalous')}</span>
												{:else}
													<span class="badge badge-success">✅ {$tr('wifiDeauthDetector.normal')}</span>
												{/if}
												<span class="channel-ratio">Deauth: {(ch.deauth_ratio * 100).toFixed(1)}%</span>
											</div>
											<div class="mini-stats">
												<div class="mini-stat"><span class="mini-val">{ch.total_packets}</span><span class="mini-label">{$tr('wifiDeauthDetector.totalPackets')}</span></div>
												<div class="mini-stat"><span class="mini-val" style="color:{ch.deauth_packets > 0 ? '#ef4444' : '#22c55e'};">{ch.deauth_packets}</span><span class="mini-label">Deauth</span></div>
												<div class="mini-stat"><span class="mini-val">{ch.access_points.length}</span><span class="mini-label">AP</span></div>
											</div>
											{#if ch.access_points.length > 0}
												<div class="tag-list">
													{#each ch.access_points as ap}
														<span class="tag">{ap}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<p class="empty-text">{$tr('wifiDeauthDetector.noChannelData')}</p>
							{/if}
						{/if}

						{#if activeResultTab === 'findings'}
							{#if result.security_findings.length > 0}
								<div class="detail-grid">
									{#each result.security_findings as finding}
										<div class="detail-card" style="border-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
											<div class="finding-header">
												<span class="finding-dot" style="background:{getSeverityColor(finding.severity)};"></span>
												<span class="finding-cat">{finding.category}</span>
												<span class="finding-severity" style="color:{getSeverityColor(finding.severity)};">{finding.severity.toUpperCase()}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-recommendation">💡 {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="alert-success-box">
									✅ {$tr('wifiDeauthDetector.noFindings')}
								</div>
							{/if}
						{/if}
					</div>
				{:else if !processing}
					<div class="section-card empty-state">
						<div class="empty-icon">📡</div>
						<h3 class="empty-title">{$tr('wifiDeauthDetector.title')}</h3>
						<p class="empty-desc">{$tr('wifiDeauthDetector.emptyHint')}</p>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="wifi_deauth_detector" toolName={$tr('sidebar.wifiDeauthDetector')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="wifi_deauth_detector" />
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
		margin: 0 0 1rem;
	}

	.section-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0.75rem;
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

	.target-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.35rem;
	}

	.target-chip {
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

	.target-chip.active {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.target-chip input[type='checkbox'] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.target-chip:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
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

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		transform: none;
		box-shadow: none;
	}

	.btn-secondary {
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
		font-weight: 500;
		padding: 0.65rem 1.25rem;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.loading-hint {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-top: 0.25rem;
		display: block;
	}

	.progress-section {
		margin-top: 0.75rem;
	}

	.progress-bar-track {
		width: 100%;
		height: 4px;
		background: rgba(148, 163, 184, 0.15);
		border-radius: 2px;
		overflow: hidden;
	}

	.progress-bar-fill {
		height: 100%;
		background: linear-gradient(90deg, #a855f7, #6366f1);
		border-radius: 2px;
		transition: width 0.5s ease;
	}

	.progress-text {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-top: 0.3rem;
		text-align: center;
	}

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
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
		color: #fca5a5;
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.error-icon { font-size: 1.25rem; }

	.score-section { margin-bottom: 1rem; }

	.score-row {
		display: flex;
		align-items: center;
		gap: 1.25rem;
	}

	.score-circle {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		border: 3px solid;
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

	.score-label {
		font-size: 0.65rem;
		margin-top: 0.15rem;
		opacity: 0.8;
	}

	.score-details { flex: 1; }

	.result-summary {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0.5rem;
	}

	.score-badges {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	.badge {
		padding: 0.2rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
	}

	.badge-danger { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
	.badge-warning { background: rgba(234, 179, 8, 0.15); color: #fde047; }
	.badge-info { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
	.badge-success { background: rgba(34, 197, 94, 0.15); color: #86efac; }

	.export-group {
		display: flex;
		gap: 0.35rem;
		align-items: center;
		flex-shrink: 0;
	}

	.export-select {
		padding: 0.4rem 0.5rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.75rem;
	}

	.btn-export {
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		border-radius: 0.4rem;
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.stats-section { margin-bottom: 1rem; }

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
	}

	.stat-card {
		text-align: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.5);
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-top: 0.25rem;
	}

	.alert-attack {
		background: rgba(239, 68, 68, 0.08);
		border-color: rgba(239, 68, 68, 0.3);
		margin-bottom: 1rem;
	}

	.attack-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.attack-icon { font-size: 1.25rem; }

	.attack-type {
		font-weight: 600;
		color: #fca5a5;
		font-size: 0.9rem;
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		flex-wrap: wrap;
		margin-bottom: 1rem;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.detail-card {
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
	}

	.subsection-title {
		font-size: 0.85rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 0.5rem;
	}

	.mini-stats {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.5rem;
	}

	.mini-stat { text-align: center; }

	.mini-val { display: block; font-size: 1.1rem; font-weight: 700; }

	.mini-label { font-size: 0.65rem; color: #94a3b8; }

	.findings-compact {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.finding-compact {
		display: flex;
		align-items: baseline;
		gap: 0.35rem;
		font-size: 0.75rem;
	}

	.finding-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.finding-cat { color: #e2e8f0; font-weight: 500; }
	.finding-sep { color: #64748b; }
	.finding-desc { color: #94a3b8; }

	.finding-more {
		font-size: 0.7rem;
		color: #94a3b8;
		text-align: center;
		padding: 0.25rem;
	}

	.finding-header {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin-bottom: 0.35rem;
	}

	.finding-severity {
		font-size: 0.65rem;
		font-weight: 700;
		padding: 0.1rem 0.35rem;
		border-radius: 0.15rem;
	}

	.finding-desc {
		font-size: 0.8rem;
		color: #e2e8f0;
		margin: 0 0 0.25rem;
	}

	.finding-recommendation {
		font-size: 0.75rem;
		color: #86efac;
		margin: 0;
	}

	.channel-grid {
		display: grid;
		grid-template-columns: repeat(6, 1fr);
		gap: 0.35rem;
	}

	.channel-chip {
		text-align: center;
		padding: 0.5rem;
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.8);
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.channel-chip.channel-anomalous {
		background: rgba(239, 68, 68, 0.1);
		border-color: rgba(239, 68, 68, 0.3);
	}

	.channel-num {
		font-size: 0.8rem;
		font-weight: 700;
		color: #e2e8f0;
	}

	.channel-num.text-danger { color: #ef4444; }

	.channel-info {
		font-size: 0.6rem;
		color: #94a3b8;
		margin-top: 0.15rem;
	}

	.channel-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.channel-title {
		font-weight: 600;
		font-size: 0.85rem;
		color: #f1f5f9;
	}

	.channel-ratio {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-left: auto;
	}

	.alert-meta {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.25rem;
		font-size: 0.7rem;
		color: #94a3b8;
		margin: 0.5rem 0;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.data-table {
		width: 100%;
		font-size: 0.8rem;
		border-collapse: collapse;
	}

	.data-table th {
		text-align: left;
		padding: 0.5rem 0.75rem;
		color: #94a3b8;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		border-bottom: 1px solid rgba(148, 163, 184, 0.15);
	}

	.data-table td {
		padding: 0.4rem 0.75rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.08);
	}

	.data-table .row-danger {
		background: rgba(239, 68, 68, 0.05);
	}

	.tag-list { display: flex; flex-wrap: wrap; gap: 0.35rem; }

	.tag {
		padding: 0.2rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-family: 'JetBrains Mono', monospace;
		background: rgba(148, 163, 184, 0.1);
		color: #cbd5e1;
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.tag-danger { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239, 68, 68, 0.2); }
	.tag-cyan { background: rgba(6, 182, 212, 0.15); color: #67e8f9; border-color: rgba(6, 182, 212, 0.2); }
	.tag-success { background: rgba(34, 197, 94, 0.15); color: #86efac; border-color: rgba(34, 197, 94, 0.2); }
	.tag-warning { background: rgba(234, 179, 8, 0.15); color: #fde047; border-color: rgba(234, 179, 8, 0.2); }

	.mono-blue { font-family: 'JetBrains Mono', monospace; color: #93c5fd; }
	.mono-green { font-family: 'JetBrains Mono', monospace; color: #86efac; }
	.mono-small { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #c4b5fd; word-break: break-all; }

	.text-center { text-align: center; }
	.text-danger { color: #ef4444; }
	.text-success { color: #22c55e; }
	.text-muted { color: #64748b; }
	.text-xs { font-size: 0.7rem; }
	.font-bold { font-weight: 700; }

	.alert-success-box {
		background: rgba(34, 197, 94, 0.08);
		border: 1px solid rgba(34, 197, 94, 0.2);
		padding: 1rem;
		border-radius: 0.5rem;
		color: #86efac;
		font-size: 0.85rem;
	}

	.empty-state {
		text-align: center;
		padding: 3rem 1.5rem;
	}

	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; }

	.empty-title {
		font-size: 1.1rem;
		color: #94a3b8;
		margin: 0 0 0.5rem;
	}

	.empty-desc {
		font-size: 0.8rem;
		color: #64748b;
	}

	.empty-text {
		font-size: 0.8rem;
		color: #64748b;
		margin: 0;
	}

	.timeline {
		position: relative;
		padding-left: 1.5rem;
	}

	.timeline::before {
		content: '';
		position: absolute;
		left: 5px;
		top: 0;
		bottom: 0;
		width: 2px;
		background: rgba(148, 163, 184, 0.2);
	}

	.timeline-item {
		position: relative;
		padding-bottom: 0.5rem;
	}

	.timeline-dot {
		position: absolute;
		left: -1.5rem;
		top: 4px;
		width: 10px;
		height: 10px;
		border-radius: 50%;
		border: 2px solid rgba(15, 23, 42, 0.8);
	}

	.timeline-content {
		padding: 0.35rem 0.5rem;
		border-radius: 0.3rem;
		background: rgba(15, 23, 42, 0.5);
		border: 1px solid rgba(148, 163, 184, 0.1);
	}

	.timeline-item.timeline-danger .timeline-content {
		border-color: rgba(239, 68, 68, 0.2);
		background: rgba(239, 68, 68, 0.05);
	}

	.timeline-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.15rem;
	}

	.timeline-time {
		font-size: 0.7rem;
		color: #94a3b8;
		font-family: 'JetBrains Mono', monospace;
	}

	.timeline-type {
		font-size: 0.7rem;
		color: #e2e8f0;
		font-weight: 500;
	}

	.timeline-detail {
		font-size: 0.7rem;
		color: #94a3b8;
		display: flex;
		align-items: center;
		gap: 0.35rem;
		flex-wrap: wrap;
	}

	.timeline-more {
		font-size: 0.7rem;
		color: #94a3b8;
		text-align: center;
		padding: 0.5rem;
	}

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.detail-grid { grid-template-columns: 1fr; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
		.mini-stats { grid-template-columns: repeat(2, 1fr); }
		.channel-grid { grid-template-columns: repeat(3, 1fr); }
		.score-row { flex-direction: column; align-items: flex-start; }
	}
</style>
