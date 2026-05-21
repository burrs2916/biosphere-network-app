<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface IpLeakInfo {
		real_ip: string; public_ip: string; is_leaking: boolean;
		isp: string; country: string; city: string;
		latitude: number; longitude: number; timezone: string;
		is_vpn: boolean; is_proxy: boolean; is_tor: boolean;
		ip_type: string; asn: string; org: string;
	}

	interface DnsLeakTest {
		test_server: string; resolved_by: string; is_leak: boolean;
	}

	interface DnsLeakInfo {
		is_leaking: boolean; dns_servers: string[]; real_dns: string[];
		leak_count: number; test_results: DnsLeakTest[];
		external_dns_queries: string[]; dns_over_https: boolean; dns_over_tls: boolean;
	}

	interface WebRtcLeakInfo {
		is_leaking: boolean; local_ips: string[]; public_ips: string[];
		leak_type: string; stun_server_reachable: boolean;
	}

	interface BrowserFingerprint {
		user_agent: string; screen_resolution: string; platform: string;
		language: string; languages: string[]; plugins_count: number;
		canvas_hash: string; webgl_hash: string; audio_hash: string;
		font_count: number; uniqueness_score: number; timezone: string;
		do_not_track: boolean; cookie_enabled: boolean;
		hardware_concurrency: number; device_memory: number | null;
	}

	interface ProxyInfo {
		is_detected: boolean; detected: boolean; proxy_type: string;
		proxy_headers: string[]; anonymity_level: string; risk_level: string;
		proxy_ip: string; forwarding_detected: boolean;
	}

	interface TorInfo {
		is_tor_exit: boolean; tor_detected: boolean; exit_node: string | null;
		connection_secure: boolean; relay_count: number; exit_country: string | null;
	}

	interface VpnInfo {
		vpn_detected: boolean; vpn_provider: string | null; encryption_level: string;
		kill_switch: boolean; dns_protected: boolean; ip_shared: boolean; hosting_provider: boolean;
	}

	interface AnonymityIssue {
		category: string; issue: string; description: string;
		severity: string; recommendation: string; confidence: number; mitre_id: string;
	}

	interface AnonymityCheckerResult {
		success: boolean; anonymity_score: number; anonymity_level: string;
		ip_leak: IpLeakInfo;
		dns_leak: DnsLeakInfo;
		webrtc_leak: WebRtcLeakInfo;
		browser_fingerprint: BrowserFingerprint;
		proxy: ProxyInfo;
		tor: TorInfo;
		vpn: VpnInfo;
		issues: AnonymityIssue[]; summary: string;
	}

	let checkIpLeak = $state(true);
	let checkDnsLeak = $state(true);
	let checkWebRtcLeak = $state(true);
	let checkFingerprint = $state(true);
	let checkProxy = $state(true);
	let checkTor = $state(true);
	let checkVpn = $state(true);
	let proxyHost = $state('');
	let proxyPort = $state('');
	let result: AnonymityCheckerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let exportFormat = $state('json');
	let exporting = $state(false);
	let historyComponent: ToolHistory = $state(null!);

	let scoreColor = $derived.by(() => {
		if (!result) return '#6b7280';
		const s = result.anonymity_score;
		if (s >= 0.9) return '#22c55e';
		if (s >= 0.7) return '#3b82f6';
		if (s >= 0.5) return '#f59e0b';
		if (s >= 0.3) return '#ef4444';
		return '#dc2626';
	});

	let scoreLabel = $derived.by(() => {
		if (!result) return '';
		const levels: Record<string, string> = {
			'excellent': $tr('anonymityChecker.levels.excellent'),
			'high': $tr('anonymityChecker.levels.high'),
			'medium': $tr('anonymityChecker.levels.medium'),
			'low': $tr('anonymityChecker.levels.low'),
			'critical': $tr('anonymityChecker.levels.critical'),
		};
		return levels[result.anonymity_level] || result.anonymity_level;
	});

	async function check() {
		processing = true;
		error = '';
		result = null;
		activeResultTab = 'overview';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const config: Record<string, unknown> = {
				check_ip_leak: checkIpLeak,
				check_dns_leak: checkDnsLeak,
				check_webrtc_leak: checkWebRtcLeak,
				check_browser_fingerprint: checkFingerprint,
				check_proxy: checkProxy,
				check_tor: checkTor,
				check_vpn: checkVpn,
				proxy_host: proxyHost.trim() || null,
				proxy_port: proxyPort.trim() ? parseInt(proxyPort.trim()) : null,
				target_url: null,
				timeout: 15,
			};
			result = await invoke<AnonymityCheckerResult>('check_anonymity_command', { config });
			if (result && historyComponent) {
				await historyComponent.saveHistory('Anonymity Check', JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory('Anonymity Check', JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		result = null;
		error = '';
		proxyHost = '';
		proxyPort = '';
	}

	function getSeverityColor(s: string): string {
		switch (s) {
			case 'critical': return '#dc2626';
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#3b82f6';
			case 'info': return '#6b7280';
			default: return '#6b7280';
		}
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			let content: string;
			let filename: string;
			if (exportFormat === 'csv') {
				const headers = ['Category', 'Issue', 'Description', 'Severity', 'Confidence', 'MITRE ID', 'Recommendation'];
				const rows = result.issues.map(i => [i.category, i.issue, i.description, i.severity, i.confidence.toFixed(2), i.mitre_id, i.recommendation]);
				content = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
				filename = 'anonymity_check.csv';
			} else {
				content = JSON.stringify(result, null, 2);
				filename = 'anonymity_check.json';
			}
			const blob = new Blob([content], { type: exportFormat === 'csv' ? 'text/csv' : 'application/json' });
			const a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = filename;
			a.click();
			URL.revokeObjectURL(a.href);
		} finally {
			exporting = false;
		}
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🛡️ {$tr('anonymityChecker.title')}</h1>
			<p class="page-subtitle">{$tr('anonymityChecker.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('anonymityChecker.check')}
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
					<h2 class="section-title">{$tr('anonymityChecker.configTitle')}</h2>
					<p class="section-desc">{$tr('anonymityChecker.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('anonymityChecker.checkOptions')}</label>
						<div class="check-grid">
							<label class="check-chip {checkIpLeak ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkIpLeak} disabled={processing} />
								🌐 {$tr('anonymityChecker.checkIpLeak')}
							</label>
							<label class="check-chip {checkDnsLeak ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDnsLeak} disabled={processing} />
								🔍 {$tr('anonymityChecker.checkDnsLeak')}
							</label>
							<label class="check-chip {checkWebRtcLeak ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkWebRtcLeak} disabled={processing} />
								📡 {$tr('anonymityChecker.checkWebRtcLeak')}
							</label>
							<label class="check-chip {checkFingerprint ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkFingerprint} disabled={processing} />
								🖐️ {$tr('anonymityChecker.checkFingerprint')}
							</label>
							<label class="check-chip {checkProxy ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkProxy} disabled={processing} />
								🔄 {$tr('anonymityChecker.checkProxy')}
							</label>
							<label class="check-chip {checkTor ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkTor} disabled={processing} />
								🧅 {$tr('anonymityChecker.checkTor')}
							</label>
							<label class="check-chip {checkVpn ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkVpn} disabled={processing} />
								🔒 {$tr('anonymityChecker.checkVpn')}
							</label>
						</div>
					</div>

					{#if checkProxy}
						<div class="form-group">
							<label class="form-label" for="ac-proxy-host">{$tr('anonymityChecker.proxyHost')}</label>
							<input id="ac-proxy-host" type="text" bind:value={proxyHost} placeholder={$tr('anonymityChecker.proxyHostPlaceholder')} class="form-input" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label" for="ac-proxy-port">{$tr('anonymityChecker.proxyPort')}</label>
							<input id="ac-proxy-port" type="text" bind:value={proxyPort} placeholder="8080" class="form-input" disabled={processing} />
						</div>
					{/if}

					<div class="button-group">
						<button class="btn-primary" onclick={check} disabled={processing}>
							{#if processing}⏳ {$tr('anonymityChecker.checking')}{:else}🛡️ {$tr('anonymityChecker.check')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('common.clear')}</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-banner">
							<span class="error-icon">⚠️</span>
							<span>{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card score-section">
						<div class="score-row">
							<div class="score-circle" style="border-color: {scoreColor}">
								<span class="score-number" style="color: {scoreColor}">{Math.round(result.anonymity_score * 100)}</span>
								<span class="score-max">%</span>
							</div>
							<div class="score-details">
								<div class="score-level" style="color: {scoreColor}">{scoreLabel}</div>
								<div class="score-stats">
									<span class="stat-item">⚠️ {$tr('anonymityChecker.issues')}: {result.issues.length}</span>
									<span class="stat-item">{result.ip_leak.is_leaking ? '🚨' : '✅'} IP {$tr('anonymityChecker.leakStatus.' + (result.ip_leak.is_leaking ? 'detected' : 'safe'))}</span>
									<span class="stat-item">{result.dns_leak.is_leaking ? '🚨' : '✅'} DNS {$tr('anonymityChecker.leakStatus.' + (result.dns_leak.is_leaking ? 'detected' : 'safe'))}</span>
									<span class="stat-item">{result.webrtc_leak.is_leaking ? '🚨' : '✅'} WebRTC {$tr('anonymityChecker.leakStatus.' + (result.webrtc_leak.is_leaking ? 'detected' : 'safe'))}</span>
								</div>
								<div class="score-total">{result.summary}</div>
							</div>
							<div class="export-group">
								<select bind:value={exportFormat} class="export-select">
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" onclick={exportResult} disabled={exporting}>
									{#if exporting}⏳{:else}📥{/if} {$tr('anonymityChecker.export')}
								</button>
							</div>
						</div>
					</div>

					{#if result.issues.filter(i => i.severity === 'critical' || i.severity === 'high').length > 0}
						<div class="section-card warning-section">
							<h3 class="warning-title">🚨 {$tr('anonymityChecker.criticalFindings')}</h3>
							<div class="warning-list">
								{#each result.issues.filter(i => i.severity === 'critical' || i.severity === 'high') as issue}
									<div class="warning-item" style="border-left-color: {getSeverityColor(issue.severity)}">
										<span class="warning-severity" style="background: {getSeverityColor(issue.severity)}">{issue.severity.toUpperCase()}</span>
										<span class="warning-text">{issue.category}: {issue.issue}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<div class="section-card">
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								📊 {$tr('anonymityChecker.tabs.overview')}
							</button>
							<button class="result-tab {activeResultTab === 'issues' ? 'active' : ''}" onclick={() => activeResultTab = 'issues'}>
								⚠️ {$tr('anonymityChecker.tabs.issues')} ({result.issues.length})
							</button>
							<button class="result-tab {activeResultTab === 'ip' ? 'active' : ''}" onclick={() => activeResultTab = 'ip'}>
								🌐 {$tr('anonymityChecker.tabs.ip')}
							</button>
							<button class="result-tab {activeResultTab === 'dns' ? 'active' : ''}" onclick={() => activeResultTab = 'dns'}>
								🔍 {$tr('anonymityChecker.tabs.dns')}
							</button>
							<button class="result-tab {activeResultTab === 'webrtc' ? 'active' : ''}" onclick={() => activeResultTab = 'webrtc'}>
								📡 {$tr('anonymityChecker.tabs.webrtc')}
							</button>
							<button class="result-tab {activeResultTab === 'fingerprint' ? 'active' : ''}" onclick={() => activeResultTab = 'fingerprint'}>
								🖐️ {$tr('anonymityChecker.tabs.fingerprint')}
							</button>
							<button class="result-tab {activeResultTab === 'network' ? 'active' : ''}" onclick={() => activeResultTab = 'network'}>
								🔒 {$tr('anonymityChecker.tabs.network')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="info-grid">
								<div class="info-card">
									<h3>🌐 {$tr('anonymityChecker.ip.title')}</h3>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.publicIp')}</span>
										<span class="info-value mono">{result.ip_leak.public_ip || 'N/A'}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.ipType')}</span>
										<span class="info-value">{result.ip_leak.ip_type || 'N/A'}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.vpn')}</span>
										<span class="info-value" style="color: {result.ip_leak.is_vpn ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_vpn ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.proxy')}</span>
										<span class="info-value" style="color: {result.ip_leak.is_proxy ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_proxy ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.tor')}</span>
										<span class="info-value" style="color: {result.ip_leak.is_tor ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_tor ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span>
									</div>
								</div>

								<div class="info-card">
									<h3>🔍 {$tr('anonymityChecker.dns.title')}</h3>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.dns.leakStatus')}</span>
										<span class="info-value" style="color: {result.dns_leak.is_leaking ? '#ef4444' : '#22c55e'}">{result.dns_leak.is_leaking ? '⚠️ ' + $tr('anonymityChecker.leakStatus.detected') : '✅ ' + $tr('anonymityChecker.leakStatus.safe')}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.dns.leakCount')}</span>
										<span class="info-value">{result.dns_leak.leak_count}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.dns.doh')}</span>
										<span class="info-value" style="color: {result.dns_leak.dns_over_https ? '#22c55e' : '#ef4444'}">{result.dns_leak.dns_over_https ? '✅' : '❌'}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.dns.dot')}</span>
										<span class="info-value" style="color: {result.dns_leak.dns_over_tls ? '#22c55e' : '#ef4444'}">{result.dns_leak.dns_over_tls ? '✅' : '❌'}</span>
									</div>
								</div>

								<div class="info-card">
									<h3>📡 {$tr('anonymityChecker.webrtc.title')}</h3>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.webrtc.leakStatus')}</span>
										<span class="info-value" style="color: {result.webrtc_leak.is_leaking ? '#ef4444' : '#22c55e'}">{result.webrtc_leak.is_leaking ? '⚠️ ' + $tr('anonymityChecker.leakStatus.detected') : '✅ ' + $tr('anonymityChecker.leakStatus.safe')}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.webrtc.stun')}</span>
										<span class="info-value">{result.webrtc_leak.stun_server_reachable ? '🔓 ' + $tr('anonymityChecker.webrtc.reachable') : '🔒 ' + $tr('anonymityChecker.webrtc.blocked')}</span>
									</div>
								</div>

								<div class="info-card">
									<h3>🔒 {$tr('anonymityChecker.network.title')}</h3>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.proxy')}</span>
										<span class="info-value">{result.proxy.detected ? `✅ ${result.proxy.proxy_type}` : '❌'}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.tor')}</span>
										<span class="info-value">{result.tor.tor_detected ? `✅ ${result.tor.exit_node || ''}` : '❌'}</span>
									</div>
									<div class="info-row">
										<span class="info-label">{$tr('anonymityChecker.ip.vpn')}</span>
										<span class="info-value">{result.vpn.vpn_detected ? `✅ ${result.vpn.vpn_provider || ''}` : '❌'}</span>
									</div>
								</div>
							</div>
						{:else if activeResultTab === 'issues'}
							{#if result.issues.length > 0}
								<div class="items-list">
									{#each result.issues as issue}
										<div class="item-card" style="border-left-color: {getSeverityColor(issue.severity)}">
											<div class="item-header">
												<span class="severity-badge" style="background: {getSeverityColor(issue.severity)}">{issue.severity.toUpperCase()}</span>
												<span class="item-title">{issue.category}: {issue.issue}</span>
												{#if issue.mitre_id}
													<span class="mitre-tag">{issue.mitre_id}</span>
												{/if}
											</div>
											<p class="item-desc">{issue.description}</p>
											<p class="item-rec">💡 {issue.recommendation}</p>
											<div class="item-footer">
												<span class="confidence-bar">
													<span class="confidence-fill" style="width: {issue.confidence * 100}%; background: {getSeverityColor(issue.severity)}"></span>
												</span>
												<span class="confidence-text">{(issue.confidence * 100).toFixed(0)}%</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">✅</div>
									<p>{$tr('anonymityChecker.noIssues')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'ip'}
							<div class="info-grid">
								<div class="info-card">
									<h3>🌐 {$tr('anonymityChecker.ip.detailTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.publicIp')}</span><span class="info-value mono">{result.ip_leak.public_ip || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.ipType')}</span><span class="info-value">{result.ip_leak.ip_type || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.isp')}</span><span class="info-value">{result.ip_leak.isp || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.org')}</span><span class="info-value">{result.ip_leak.org || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.asn')}</span><span class="info-value">{result.ip_leak.asn || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.country')}</span><span class="info-value">{result.ip_leak.country || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.city')}</span><span class="info-value">{result.ip_leak.city || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.timezone')}</span><span class="info-value">{result.ip_leak.timezone || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.location')}</span><span class="info-value">{result.ip_leak.latitude && result.ip_leak.longitude ? `${result.ip_leak.latitude}, ${result.ip_leak.longitude}` : 'N/A'}</span></div>
								</div>
								<div class="info-card">
									<h3>🔒 {$tr('anonymityChecker.ip.privacyTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.vpn')}</span><span class="info-value" style="color: {result.ip_leak.is_vpn ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_vpn ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.proxy')}</span><span class="info-value" style="color: {result.ip_leak.is_proxy ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_proxy ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.tor')}</span><span class="info-value" style="color: {result.ip_leak.is_tor ? '#22c55e' : '#ef4444'}">{result.ip_leak.is_tor ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.ip.leaking')}</span><span class="info-value" style="color: {result.ip_leak.is_leaking ? '#ef4444' : '#22c55e'}">{result.ip_leak.is_leaking ? '⚠️ ' + $tr('anonymityChecker.leakStatus.detected') : '✅ ' + $tr('anonymityChecker.leakStatus.safe')}</span></div>
								</div>
							</div>
						{:else if activeResultTab === 'dns'}
							<div class="info-grid">
								<div class="info-card">
									<h3>🔍 {$tr('anonymityChecker.dns.detailTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.dns.leakStatus')}</span><span class="info-value" style="color: {result.dns_leak.is_leaking ? '#ef4444' : '#22c55e'}">{result.dns_leak.is_leaking ? '⚠️ ' + $tr('anonymityChecker.leakStatus.detected') : '✅ ' + $tr('anonymityChecker.leakStatus.safe')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.dns.leakCount')}</span><span class="info-value">{result.dns_leak.leak_count}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.dns.doh')}</span><span class="info-value" style="color: {result.dns_leak.dns_over_https ? '#22c55e' : '#ef4444'}">{result.dns_leak.dns_over_https ? '✅' : '❌'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.dns.dot')}</span><span class="info-value" style="color: {result.dns_leak.dns_over_tls ? '#22c55e' : '#ef4444'}">{result.dns_leak.dns_over_tls ? '✅' : '❌'}</span></div>
								</div>
								<div class="info-card">
									<h3>📋 {$tr('anonymityChecker.dns.servers')}</h3>
									{#if result.dns_leak.dns_servers.length > 0}
										{#each result.dns_leak.dns_servers as server}
											<div class="tag-item">{server}</div>
										{/each}
									{:else}
										<div class="info-row"><span class="info-value">N/A</span></div>
									{/if}
								</div>
							</div>
							{#if result.dns_leak.test_results.length > 0}
								<div class="info-card" style="margin-top: 12px;">
									<h3>🧪 {$tr('anonymityChecker.dns.testResults')}</h3>
									<div class="test-results-list">
										{#each result.dns_leak.test_results as test}
											<div class="test-result-item" style="border-left-color: {test.is_leak ? '#ef4444' : '#22c55e'}">
												<span class="test-status">{test.is_leak ? '🔴' : '🟢'}</span>
												<span class="test-info">{test.test_server} → {test.resolved_by}</span>
											</div>
										{/each}
									</div>
								</div>
							{/if}
						{:else if activeResultTab === 'webrtc'}
							<div class="info-grid">
								<div class="info-card">
									<h3>📡 {$tr('anonymityChecker.webrtc.detailTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.webrtc.leakStatus')}</span><span class="info-value" style="color: {result.webrtc_leak.is_leaking ? '#ef4444' : '#22c55e'}">{result.webrtc_leak.is_leaking ? '⚠️ ' + $tr('anonymityChecker.leakStatus.detected') : '✅ ' + $tr('anonymityChecker.leakStatus.safe')}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.webrtc.leakType')}</span><span class="info-value">{result.webrtc_leak.leak_type || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.webrtc.stun')}</span><span class="info-value">{result.webrtc_leak.stun_server_reachable ? '🔓 ' + $tr('anonymityChecker.webrtc.reachable') : '🔒 ' + $tr('anonymityChecker.webrtc.blocked')}</span></div>
								</div>
								<div class="info-card">
									<h3>🌐 {$tr('anonymityChecker.webrtc.exposedIps')}</h3>
									{#if result.webrtc_leak.local_ips.length > 0}
										<h4 style="font-size: 0.8rem; color: #94a3b8; margin: 0 0 6px;">{$tr('anonymityChecker.webrtc.localIps')}</h4>
										{#each result.webrtc_leak.local_ips as ip}
											<div class="tag-item warning">{ip}</div>
										{/each}
									{/if}
									{#if result.webrtc_leak.public_ips.length > 0}
										<h4 style="font-size: 0.8rem; color: #94a3b8; margin: 8px 0 6px;">{$tr('anonymityChecker.webrtc.publicIps')}</h4>
										{#each result.webrtc_leak.public_ips as ip}
											<div class="tag-item warning">{ip}</div>
										{/each}
									{/if}
									{#if result.webrtc_leak.local_ips.length === 0 && result.webrtc_leak.public_ips.length === 0}
										<div class="info-row"><span class="info-value" style="color: #22c55e;">✅ {$tr('anonymityChecker.webrtc.noLeak')}</span></div>
									{/if}
								</div>
							</div>
						{:else if activeResultTab === 'fingerprint'}
							<div class="info-grid">
								<div class="info-card">
									<h3>🖐️ {$tr('anonymityChecker.fingerprint.detailTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.ua')}</span><span class="info-value mono" style="font-size: 0.8rem; word-break: break-all;">{result.browser_fingerprint.user_agent || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.platform')}</span><span class="info-value">{result.browser_fingerprint.platform || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.language')}</span><span class="info-value">{result.browser_fingerprint.languages.length > 0 ? result.browser_fingerprint.languages.join(', ') : result.browser_fingerprint.language || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.resolution')}</span><span class="info-value">{result.browser_fingerprint.screen_resolution || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.timezone')}</span><span class="info-value">{result.browser_fingerprint.timezone || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.plugins')}</span><span class="info-value">{result.browser_fingerprint.plugins_count}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.fonts')}</span><span class="info-value">{result.browser_fingerprint.font_count}</span></div>
								</div>
								<div class="info-card">
									<h3>🎯 {$tr('anonymityChecker.fingerprint.uniqueness')}</h3>
									<div class="uniqueness-display">
										<div class="uniqueness-circle" style="border-color: {result.browser_fingerprint.uniqueness_score > 0.7 ? '#ef4444' : result.browser_fingerprint.uniqueness_score > 0.4 ? '#f59e0b' : '#22c55e'}">
											<span class="uniqueness-value" style="color: {result.browser_fingerprint.uniqueness_score > 0.7 ? '#ef4444' : result.browser_fingerprint.uniqueness_score > 0.4 ? '#f59e0b' : '#22c55e'}">{(result.browser_fingerprint.uniqueness_score * 100).toFixed(0)}%</span>
										</div>
										<p class="uniqueness-desc">{result.browser_fingerprint.uniqueness_score > 0.7 ? $tr('anonymityChecker.fingerprint.highUniqueness') : result.browser_fingerprint.uniqueness_score > 0.4 ? $tr('anonymityChecker.fingerprint.mediumUniqueness') : $tr('anonymityChecker.fingerprint.lowUniqueness')}</p>
									</div>
									<div class="info-row" style="margin-top: 8px;"><span class="info-label">{$tr('anonymityChecker.fingerprint.canvas')}</span><span class="info-value mono" style="font-size: 0.75rem;">{result.browser_fingerprint.canvas_hash || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.webgl')}</span><span class="info-value mono" style="font-size: 0.75rem;">{result.browser_fingerprint.webgl_hash || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.fingerprint.audio')}</span><span class="info-value mono" style="font-size: 0.75rem;">{result.browser_fingerprint.audio_hash || 'N/A'}</span></div>
								</div>
							</div>
						{:else if activeResultTab === 'network'}
							<div class="info-grid">
								<div class="info-card">
									<h3>🔄 {$tr('anonymityChecker.proxy.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.proxy.detected')}</span><span class="info-value" style="color: {result.proxy.detected ? '#22c55e' : '#94a3b8'}">{result.proxy.detected ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									{#if result.proxy.detected}
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.proxy.type')}</span><span class="info-value">{result.proxy.proxy_type}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.proxy.anonymity')}</span><span class="info-value">{result.proxy.anonymity_level}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.proxy.ip')}</span><span class="info-value mono">{result.proxy.proxy_ip || 'N/A'}</span></div>
										{#if result.proxy.proxy_headers.length > 0}
											<div class="info-row"><span class="info-label">{$tr('anonymityChecker.proxy.headers')}</span></div>
											{#each result.proxy.proxy_headers as header}
												<div class="tag-item warning">{header}</div>
											{/each}
										{/if}
									{/if}
								</div>
								<div class="info-card">
									<h3>🧅 {$tr('anonymityChecker.tor.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.tor.detected')}</span><span class="info-value" style="color: {result.tor.tor_detected ? '#22c55e' : '#94a3b8'}">{result.tor.tor_detected ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									{#if result.tor.tor_detected}
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.tor.exitNode')}</span><span class="info-value mono">{result.tor.exit_node || 'N/A'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.tor.exitCountry')}</span><span class="info-value">{result.tor.exit_country || 'N/A'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.tor.secure')}</span><span class="info-value" style="color: {result.tor.connection_secure ? '#22c55e' : '#ef4444'}">{result.tor.connection_secure ? '✅' : '❌'}</span></div>
									{/if}
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.tor.relayCount')}</span><span class="info-value">{result.tor.relay_count}</span></div>
								</div>
								<div class="info-card" style="grid-column: 1 / -1;">
									<h3>🔒 {$tr('anonymityChecker.vpn.title')}</h3>
									<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.detected')}</span><span class="info-value" style="color: {result.vpn.vpn_detected ? '#22c55e' : '#94a3b8'}">{result.vpn.vpn_detected ? '✅ ' + $tr('common.yes') : '❌ ' + $tr('common.no')}</span></div>
									{#if result.vpn.vpn_detected}
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.provider')}</span><span class="info-value">{result.vpn.vpn_provider || 'N/A'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.encryption')}</span><span class="info-value">{result.vpn.encryption_level || 'N/A'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.killSwitch')}</span><span class="info-value" style="color: {result.vpn.kill_switch ? '#22c55e' : '#ef4444'}">{result.vpn.kill_switch ? '✅' : '❌'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.dnsProtected')}</span><span class="info-value" style="color: {result.vpn.dns_protected ? '#22c55e' : '#ef4444'}">{result.vpn.dns_protected ? '✅' : '❌'}</span></div>
									{:else}
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.encryption')}</span><span class="info-value">{result.vpn.encryption_level || 'N/A'}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.hostingProvider')}</span><span class="info-value" style="color: {result.vpn.hosting_provider ? '#f59e0b' : '#94a3b8'}">{result.vpn.hosting_provider ? '⚠️ ' + $tr('common.yes') : $tr('common.no')}</span></div>
										<div class="info-row"><span class="info-label">{$tr('anonymityChecker.vpn.ipShared')}</span><span class="info-value" style="color: {result.vpn.ip_shared ? '#f59e0b' : '#94a3b8'}">{result.vpn.ip_shared ? '⚠️ ' + $tr('common.yes') : $tr('common.no')}</span></div>
									{/if}
								</div>
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">🛡️</div>
							<p>{$tr('anonymityChecker.noResults')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="anonymity_checker" toolName={$tr('anonymityChecker.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="anonymity_checker" />
		</div>
	{/if}
</div>

<style>
	.nd-page { padding: 1.5rem; max-width: 1400px; margin: 0 auto; min-height: 100vh; }

	.page-header { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.header-left { display: flex; flex-direction: column; gap: 4px; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.8rem; transition: color 0.2s; }
	.back-link:hover { color: #a855f7; }
	.page-title { font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0 0.25rem; color: #f1f5f9; }
	.page-subtitle { color: #94a3b8; font-size: 0.875rem; margin: 0; }

	.tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 0.25rem; }
	.tab-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: transparent; cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.tab-icon { font-size: 0.9rem; }

	.content-grid { display: grid; grid-template-columns: 340px 1fr; gap: 1.25rem; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0.75rem; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; }
	.form-input:disabled { opacity: 0.5; }

	.check-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
	.check-chip { display: flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 6px; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.5); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.check-chip:hover { border-color: rgba(168, 85, 247, 0.3); }
	.check-chip.active { border-color: rgba(168, 85, 247, 0.5); background: rgba(168, 85, 247, 0.1); color: #e2e8f0; }
	.check-chip input { display: none; }

	.button-group { display: flex; gap: 8px; margin-top: 12px; }
	.btn-primary { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; cursor: pointer; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { padding: 0.6rem 1rem; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.5rem; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; }

	.error-banner { display: flex; align-items: center; gap: 10px; padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; color: #ef4444; font-size: 0.85rem; }
	.error-icon { font-size: 1.2rem; }

	.score-section { margin-bottom: 12px; }
	.score-row { display: flex; align-items: center; gap: 20px; }
	.score-circle { width: 80px; height: 80px; border-radius: 50%; border: 4px solid; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
	.score-number { font-size: 1.5rem; font-weight: 700; }
	.score-max { font-size: 0.8rem; color: #94a3b8; }
	.score-details { flex: 1; display: flex; flex-direction: column; gap: 4px; }
	.score-level { font-weight: 600; font-size: 1rem; }
	.score-stats { display: flex; flex-wrap: wrap; gap: 8px; font-size: 0.8rem; }
	.stat-item { color: #94a3b8; }
	.score-total { font-size: 0.75rem; color: #64748b; margin-top: 2px; }
	.export-group { display: flex; gap: 6px; align-items: center; }
	.export-select { padding: 4px 8px; border-radius: 6px; border: 1px solid rgba(148, 163, 184, 0.2); background: rgba(15, 23, 42, 0.8); color: #e2e8f0; font-size: 0.8rem; }
	.btn-export { padding: 6px 12px; border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 6px; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.btn-export:hover:not(:disabled) { background: rgba(168, 85, 247, 0.2); }
	.btn-export:disabled { opacity: 0.5; }

	.warning-section { margin-bottom: 12px; border-color: rgba(239, 68, 68, 0.3); }
	.warning-title { font-size: 0.95rem; font-weight: 600; color: #ef4444; margin: 0 0 10px; }
	.warning-list { display: flex; flex-direction: column; gap: 6px; }
	.warning-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(15, 23, 42, 0.5); border-radius: 6px; border-left: 3px solid; font-size: 0.85rem; }
	.warning-severity { padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.7rem; font-weight: 600; }
	.warning-text { color: #e2e8f0; }

	.result-tabs { display: flex; gap: 4px; margin-bottom: 12px; flex-wrap: wrap; }
	.result-tab { padding: 6px 12px; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 6px; background: transparent; color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; border-color: transparent; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
	.info-card { background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 8px; padding: 12px; }
	.info-card h3 { font-size: 0.9rem; margin: 0 0 8px; color: #f1f5f9; }
	.info-row { display: flex; gap: 8px; padding: 4px 0; font-size: 0.85rem; }
	.info-label { font-weight: 600; min-width: 90px; color: #94a3b8; flex-shrink: 0; }
	.info-value { flex: 1; word-break: break-all; color: #e2e8f0; }
	.info-value.mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; }

	.tag-item { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; margin: 2px; background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.15); }
	.tag-item.warning { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border-color: rgba(245, 158, 11, 0.2); }

	.items-list { display: flex; flex-direction: column; gap: 8px; }
	.item-card { padding: 12px; background: rgba(15, 23, 42, 0.5); border-radius: 8px; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; }
	.severity-badge { padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.7rem; font-weight: 600; }
	.item-title { font-weight: 600; font-size: 0.9rem; color: #f1f5f9; }
	.mitre-tag { padding: 2px 6px; border-radius: 4px; background: rgba(59, 130, 246, 0.15); color: #60a5fa; font-size: 0.7rem; font-family: monospace; }
	.item-desc { font-size: 0.85rem; color: #94a3b8; margin: 4px 0; }
	.item-rec { font-size: 0.8rem; color: #64748b; margin: 2px 0 0; }
	.item-footer { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
	.confidence-bar { flex: 1; height: 4px; background: rgba(148, 163, 184, 0.15); border-radius: 2px; overflow: hidden; }
	.confidence-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }
	.confidence-text { font-size: 0.7rem; color: #94a3b8; min-width: 30px; }

	.test-results-list { display: flex; flex-direction: column; gap: 4px; }
	.test-result-item { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: rgba(15, 23, 42, 0.5); border-radius: 6px; border-left: 3px solid; font-size: 0.8rem; }
	.test-status { font-size: 0.8rem; }
	.test-info { color: #e2e8f0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.75rem; }

	.uniqueness-display { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 12px; }
	.uniqueness-circle { width: 70px; height: 70px; border-radius: 50%; border: 3px solid; display: flex; align-items: center; justify-content: center; }
	.uniqueness-value { font-size: 1.2rem; font-weight: 700; }
	.uniqueness-desc { font-size: 0.8rem; color: #94a3b8; margin: 0; text-align: center; }

	.empty-state { text-align: center; padding: 40px; color: #94a3b8; }
	.empty-icon { font-size: 3rem; margin-bottom: 12px; }

	@media (max-width: 900px) {
		.content-grid { grid-template-columns: 1fr; }
		.info-grid { grid-template-columns: 1fr; }
		.check-grid { grid-template-columns: 1fr; }
	}
</style>
