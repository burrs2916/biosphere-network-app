<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface BluetoothDevice {
		address: string;
		name: string;
		device_type: string;
		rssi: number;
		is_paired: boolean;
		is_connectable: boolean;
		services: string[];
		vendor: string;
	}

	interface BluetoothVulnerability {
		vulnerability_type: string;
		severity: string;
		description: string;
		affected_device: string;
		cve_id: string | null;
		remediation: string;
	}

	interface BluetoothService {
		name: string;
		uuid: string;
		service_type: string;
		is_secure: boolean;
		characteristics: string[];
	}

	interface BluetoothSecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface BluetoothScanResult {
		success: boolean;
		scan_type: string;
		devices: BluetoothDevice[];
		vulnerabilities: BluetoothVulnerability[];
		services: BluetoothService[];
		security_findings: BluetoothSecurityFinding[];
		summary: string;
	}

	let scanDuration = $state(10);
	let scanType = $state('dual');
	let checkVulnerabilities = $state(true);
	let checkServices = $state(true);
	let result: BluetoothScanResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('scan');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory;

	let highFindingCount = $derived(
		result ? (result as BluetoothScanResult).security_findings.filter(f => f.severity === 'critical' || f.severity === 'high').length : 0
	);

	function translateSeverity(sev: string): string {
		const key = `bluetoothScanner.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	function translateCategory(cat: string): string {
		const key = `bluetoothScanner.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	async function scan() {
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<BluetoothScanResult>('scan_bluetooth_command', {
				config: {
					scan_duration_secs: scanDuration,
					scan_type: scanType,
					check_vulnerabilities: checkVulnerabilities,
					check_services: checkServices,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					`BT ${scanType}`,
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory('BT Scan', '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		scanDuration = 10;
		scanType = 'dual';
		checkVulnerabilities = true;
		checkServices = true;
		result = null;
		error = '';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'critical': return '#fca5a5';
			case 'high': return '#fdba74';
			case 'medium': return '#fbbf24';
			case 'low': return '#86efac';
			default: return '#94a3b8';
		}
	}

	function getSeverityBorder(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.5)';
			case 'high': return 'rgba(249, 115, 22, 0.5)';
			case 'medium': return 'rgba(245, 158, 11, 0.5)';
			case 'low': return 'rgba(34, 197, 94, 0.5)';
			default: return 'rgba(148, 163, 184, 0.3)';
		}
	}

	function getSeverityBg(severity: string): string {
		switch (severity) {
			case 'critical': return 'rgba(239, 68, 68, 0.1)';
			case 'high': return 'rgba(249, 115, 22, 0.1)';
			case 'medium': return 'rgba(245, 158, 11, 0.1)';
			case 'low': return 'rgba(34, 197, 94, 0.1)';
			default: return 'rgba(148, 163, 184, 0.1)';
		}
	}

	function getRssiColor(rssi: number): string {
		if (rssi > -50) return '#86efac';
		if (rssi > -70) return '#fbbf24';
		return '#fca5a5';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📡 {$tr('bluetoothScanner.title')}</h1>
			<p class="page-subtitle">{$tr('bluetoothScanner.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'scan' ? 'active' : ''}" onclick={() => activeMainTab = 'scan'}>
			<span class="tab-icon">🔍</span> {$tr('bluetoothScanner.scan')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('bluetoothScanner.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('bluetoothScanner.help')}
		</button>
	</div>

	{#if activeMainTab === 'scan'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('bluetoothScanner.config.title')}</h2>
					<p class="section-desc">{$tr('bluetoothScanner.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('bluetoothScanner.scanDuration')}</label>
						<input type="number" bind:value={scanDuration} min="1" max="300" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('bluetoothScanner.scanType')}</label>
						<select bind:value={scanType} class="form-input" disabled={processing}>
							<option value="classic">{$tr('bluetoothScanner.classic')}</option>
							<option value="le">{$tr('bluetoothScanner.le')}</option>
							<option value="dual">{$tr('bluetoothScanner.dual')}</option>
						</select>
					</div>

					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkVulnerabilities} class="checkbox-input" disabled={processing} />
							<span class="checkbox-text">{$tr('bluetoothScanner.checkVulnerabilities')}</span>
						</label>
					</div>

					<div class="form-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkServices} class="checkbox-input" disabled={processing} />
							<span class="checkbox-text">{$tr('bluetoothScanner.checkServices')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={scan} disabled={processing}>
							{#if processing}<span class="spinner"></span> {$tr('bluetoothScanner.scanning')}{:else}📡 {$tr('bluetoothScanner.scan')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('bluetoothScanner.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('bluetoothScanner.scanType')}</span>
								<span class="query-text">{(result as BluetoothScanResult).scan_type.toUpperCase()}</span>
								<span class="status-badge {(result as BluetoothScanResult).success ? 'success' : 'failed'}">{(result as BluetoothScanResult).success ? $tr('bluetoothScanner.result.success') : $tr('bluetoothScanner.result.failed')}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{(result as BluetoothScanResult).devices.length} {$tr('bluetoothScanner.result.devices')}</span>
								<span class="summary-badge orange">{(result as BluetoothScanResult).vulnerabilities.length} {$tr('bluetoothScanner.result.vulnerabilities')}</span>
								{#if highFindingCount > 0}
									<span class="summary-badge red">{highFindingCount} {$tr('bluetoothScanner.result.highFindings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value purple">{(result as BluetoothScanResult).devices.length}</div>
								<div class="stat-label">{$tr('bluetoothScanner.result.devices')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value orange">{(result as BluetoothScanResult).vulnerabilities.length}</div>
								<div class="stat-label">{$tr('bluetoothScanner.result.vulnerabilities')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value blue">{(result as BluetoothScanResult).services.length}</div>
								<div class="stat-label">{$tr('bluetoothScanner.result.services')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{highFindingCount}</div>
								<div class="stat-label">{$tr('bluetoothScanner.result.highFindings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('bluetoothScanner.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'devices' ? 'active' : ''}" onclick={() => activeResultTab = 'devices'}>{$tr('bluetoothScanner.tabs.devices')} ({(result as BluetoothScanResult).devices.length})</button>
							<button class="result-tab {activeResultTab === 'vulnerabilities' ? 'active' : ''}" onclick={() => activeResultTab = 'vulnerabilities'}>{$tr('bluetoothScanner.tabs.vulnerabilities')} ({(result as BluetoothScanResult).vulnerabilities.length})</button>
							<button class="result-tab {activeResultTab === 'services' ? 'active' : ''}" onclick={() => activeResultTab = 'services'}>{$tr('bluetoothScanner.tabs.services')} ({(result as BluetoothScanResult).services.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('bluetoothScanner.tabs.findings')} ({(result as BluetoothScanResult).security_findings.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if (result as BluetoothScanResult).vulnerabilities.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('bluetoothScanner.result.vulnerabilities')} ({(result as BluetoothScanResult).vulnerabilities.length})</h3>
										<div class="detection-list">
											{#each (result as BluetoothScanResult).vulnerabilities as vuln}
												<div class="detection-item">
													<div class="detection-header">
														<span class="detection-family">{vuln.vulnerability_type}</span>
														<span class="severity-badge" style="background: {getSeverityBorder(vuln.severity)}; color: {getSeverityColor(vuln.severity)};">{translateSeverity(vuln.severity)}</span>
													</div>
													<p class="detection-desc">{vuln.description}</p>
													{#if vuln.cve_id}
														<span class="tag-item purple">{vuln.cve_id}</span>
													{/if}
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if (result as BluetoothScanResult).devices.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('bluetoothScanner.result.devices')} ({(result as BluetoothScanResult).devices.length})</h3>
										<div class="tag-grid">
											{#each (result as BluetoothScanResult).devices as device}
												<span class="tag-item {device.is_paired ? 'purple' : 'gray'}">
													{device.name || $tr('bluetoothScanner.unnamedDevice')}
													<span class="process-tag">({device.address})</span>
												</span>
											{/each}
										</div>
									</div>
								{/if}

								{#if (result as BluetoothScanResult).security_findings.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('bluetoothScanner.result.securityFindings')} ({(result as BluetoothScanResult).security_findings.length})</h3>
										<div class="finding-list">
											{#each (result as BluetoothScanResult).security_findings as finding}
												<div class="finding-item" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
													<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
													<span class="finding-category">{translateCategory(finding.category)}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'devices'}
							{#if (result as BluetoothScanResult).devices.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('bluetoothScanner.table.deviceName')}</th>
												<th>{$tr('bluetoothScanner.table.address')}</th>
												<th>{$tr('bluetoothScanner.table.type')}</th>
												<th>RSSI</th>
												<th>{$tr('bluetoothScanner.table.vendor')}</th>
												<th>{$tr('bluetoothScanner.table.status')}</th>
											</tr>
										</thead>
										<tbody>
											{#each (result as BluetoothScanResult).devices as device}
												<tr>
													<td class="device-name">{device.name || $tr('bluetoothScanner.unnamedDevice')}</td>
													<td class="mono-text">{device.address}</td>
													<td>{device.device_type}</td>
													<td style="color: {getRssiColor(device.rssi)}">{device.rssi}</td>
													<td>{device.vendor || '-'}</td>
													<td>
														<div class="status-tags">
															{#if device.is_paired}<span class="state-tag active">{$tr('bluetoothScanner.paired')}</span>{/if}
															{#if device.is_connectable}<span class="state-tag connectable">{$tr('bluetoothScanner.connectable')}</span>{/if}
														</div>
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('bluetoothScanner.result.noDevices')}</div>
							{/if}
						{:else if activeResultTab === 'vulnerabilities'}
							{#if (result as BluetoothScanResult).vulnerabilities.length > 0}
								<div class="detection-list">
									{#each (result as BluetoothScanResult).vulnerabilities as vuln}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(vuln.severity)}; background: {getSeverityBg(vuln.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{vuln.vulnerability_type}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(vuln.severity)}; color: {getSeverityColor(vuln.severity)};">{translateSeverity(vuln.severity)}</span>
											</div>
											<p class="detection-desc">{vuln.description}</p>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('bluetoothScanner.table.affectedDevice')}:</span> <span class="mono-text">{vuln.affected_device}</span></span>
												{#if vuln.cve_id}
													<span class="meta-item"><span class="mitre-tag">{vuln.cve_id}</span></span>
												{/if}
											</div>
											<p class="finding-rec">💡 {$tr('bluetoothScanner.result.remediation')}: {vuln.remediation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('bluetoothScanner.result.noVulnerabilities')}</div>
							{/if}
						{:else if activeResultTab === 'services'}
							{#if (result as BluetoothScanResult).services.length > 0}
								<div class="capability-list">
									{#each (result as BluetoothScanResult).services as svc}
										<div class="capability-card" style="border-left-color: {svc.is_secure ? 'rgba(34, 197, 94, 0.5)' : 'rgba(239, 68, 68, 0.5)'}; background: {svc.is_secure ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'};">
											<div class="capability-header">
												<span class="capability-name">{svc.name}</span>
												<span class="severity-badge" style="background: {svc.is_secure ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}; color: {svc.is_secure ? '#86efac' : '#fca5a5'};">{svc.is_secure ? $tr('bluetoothScanner.secure') : $tr('bluetoothScanner.insecure')}</span>
											</div>
											<div class="capability-meta">
												<span class="cap-category">UUID: <span class="mono-text">{svc.uuid}</span></span>
												<span class="cap-category" style="margin-left: 0.75rem;">{$tr('bluetoothScanner.serviceType')}: {svc.service_type}</span>
											</div>
											{#if svc.characteristics.length > 0}
												<div class="tag-grid" style="margin-top: 0.4rem;">
													{#each svc.characteristics as char}
														<span class="tag-item gray">{char}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('bluetoothScanner.result.noServices')}</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if (result as BluetoothScanResult).security_findings.length > 0}
								<div class="finding-list">
									{#each (result as BluetoothScanResult).security_findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
											<div class="finding-header">
												<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
												<span class="finding-category">{translateCategory(finding.category)}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">💡 {$tr('bluetoothScanner.result.recommendation')}: {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('bluetoothScanner.result.noFindings')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📡</div>
							<p>{$tr('bluetoothScanner.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="bluetooth_scanner" toolName={$tr('bluetoothScanner.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="bluetooth_scanner" />
	{/if}
</div>

<style>
	.nd-page { padding: 1.5rem; max-width: 1200px; margin: 0 auto; min-height: 100vh; }
	.page-header { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
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
	.input-section { position: sticky; top: 1.5rem; align-self: start; max-height: calc(100vh - 3rem); overflow-y: auto; }
	.result-section { min-width: 0; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }
	.form-input:disabled { opacity: 0.6; }

	.checkbox-label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }
	.checkbox-input { accent-color: #a855f7; width: 1rem; height: 1rem; }
	.checkbox-text { font-size: 0.85rem; color: #cbd5e1; }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn-primary { flex: 1; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-weight: 600; padding: 0.65rem 1.25rem; border: none; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.5rem; font-size: 0.9rem; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4); transform: translateY(-1px); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
	.btn-secondary { background: rgba(148, 163, 184, 0.1); color: #94a3b8; padding: 0.65rem 1rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
	.btn-secondary:hover:not(:disabled) { background: rgba(148, 163, 184, 0.2); color: #e2e8f0; }
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner { display: inline-block; width: 1rem; height: 1rem; border: 2px solid rgba(255, 255, 255, 0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.status-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }
	.status-badge.success { background: rgba(34, 197, 94, 0.15); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
	.status-badge.failed { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
	.summary-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.orange { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

	.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-value.purple { color: #c4b5fd; }
	.stat-value.orange { color: #fdba74; }
	.stat-value.blue { color: #93c5fd; }
	.stat-value.red { color: #fca5a5; }
	.stat-label { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 1rem; }
	.item-section-title { font-size: 0.85rem; font-weight: 600; color: #c4b5fd; margin: 0 0 0.5rem; }

	.tag-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tag-item { padding: 0.25rem 0.6rem; border-radius: 0.3rem; font-size: 0.75rem; font-weight: 500; }
	.tag-item.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.2); }
	.tag-item.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }
	.process-tag { opacity: 0.7; font-size: 0.7rem; margin-left: 0.3rem; }

	.detection-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.detection-item { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.detection-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(249, 115, 22, 0.15); border-radius: 0.5rem; border-left: 3px solid rgba(249, 115, 22, 0.5); }
	.detection-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; }
	.detection-family { font-weight: 600; color: #fdba74; font-size: 0.9rem; }
	.detection-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0 0; }
	.detection-meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.meta-item { font-size: 0.85rem; color: #cbd5e1; }
	.meta-label { color: #94a3b8; margin-right: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.severity-badge.large { font-size: 0.8rem; padding: 0.2rem 0.6rem; }

	.mitre-tag { font-size: 0.7rem; color: #c4b5fd; background: rgba(168, 85, 247, 0.1); padding: 0.1rem 0.4rem; border-radius: 0.2rem; border: 1px solid rgba(168, 85, 247, 0.2); }

	.table-wrapper { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { padding: 0.5rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.mono-text { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #93c5fd; }
	.device-name { font-weight: 500; color: #f1f5f9; }
	.status-tags { display: flex; gap: 0.3rem; }
	.state-tag { padding: 0.1rem 0.4rem; border-radius: 0.2rem; font-size: 0.75rem; background: rgba(148, 163, 184, 0.1); }
	.state-tag.active { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.state-tag.connectable { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; }

	.capability-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.capability-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.capability-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem; }
	.capability-name { font-weight: 600; color: #f1f5f9; font-size: 0.9rem; }
	.capability-meta { margin-bottom: 0.3rem; }
	.cap-category { font-size: 0.75rem; color: #94a3b8; }

	.finding-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.finding-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.finding-item { padding: 0.5rem 0.75rem; border-radius: 0.4rem; border-left: 3px solid; display: flex; align-items: center; gap: 0.5rem; }
	.finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.finding-category { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.finding-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0; }
	.finding-rec { font-size: 0.8rem; color: #86efac; margin: 0.3rem 0 0; }

	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { font-size: 0.85rem; margin: 0; }
	.empty-item { text-align: center; padding: 1.5rem; color: #64748b; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.input-section { position: static; max-height: none; }
		.stats-grid { grid-template-columns: repeat(2, 1fr); }
	}
</style>
