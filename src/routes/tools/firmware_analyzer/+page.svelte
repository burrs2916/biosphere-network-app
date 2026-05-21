<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface FirmwareInfo {
		vendor: string;
		model: string;
		version: string;
		architecture: string;
		file_size: number;
		file_type: string;
		checksum: string;
		build_date: string | null;
	}

	interface FirmwarePartition {
		name: string;
		offset: number;
		size: number;
		file_system: string;
		is_readable: boolean;
	}

	interface FirmwareCredential {
		credential_type: string;
		username: string;
		password: string;
		location: string;
		severity: string;
	}

	interface FirmwareBinary {
		name: string;
		path: string;
		architecture: string;
		is_stripped: boolean;
		has_stack_canary: boolean;
		has_nx: boolean;
		severity: string;
	}

	interface FirmwareBackdoor {
		backdoor_type: string;
		description: string;
		location: string;
		severity: string;
		indicators: string[];
	}

	interface FirmwareSecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
	}

	interface FirmwareAnalyzerResult {
		success: boolean;
		firmware_info: FirmwareInfo;
		partitions: FirmwarePartition[];
		credentials: FirmwareCredential[];
		binaries: FirmwareBinary[];
		backdoors: FirmwareBackdoor[];
		security_findings: FirmwareSecurityFinding[];
		summary: string;
	}

	let firmwarePath = $state('');
	let vendor = $state('');
	let model = $state('');
	let extractFilesystem = $state(true);
	let findCredentials = $state(true);
	let analyzeBinaries = $state(true);
	let checkBackdoors = $state(true);
	let result: FirmwareAnalyzerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory = $state(null as any);

	let highFindingCount = $derived(
		(result as FirmwareAnalyzerResult | null)?.security_findings.filter((f: FirmwareSecurityFinding) => f.severity === 'critical' || f.severity === 'high').length ?? 0
	);

	function translateSeverity(sev: string): string {
		const key = `firmwareAnalyzer.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	function translateCategory(cat: string): string {
		const key = `firmwareAnalyzer.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	async function selectFirmwareFile() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				multiple: false,
				title: $tr('firmwareAnalyzer.firmwarePath'),
				filters: [{
					name: 'Firmware',
					extensions: ['bin', 'fw', 'img', 'trx', 'chk', 'wrt', 'pat', 'elf', 'dmp', 'gz', 'tar', 'zip', 'squashfs', 'jffs2']
				}]
			});
			if (selected) {
				firmwarePath = typeof selected === 'string' ? selected : (selected as any).path || String(selected);
			}
		} catch (e) {
			console.error('File dialog failed:', e);
		}
	}

	async function analyze() {
		if (!firmwarePath.trim()) {
			error = $tr('firmwareAnalyzer.error.noPath');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<FirmwareAnalyzerResult>('analyze_firmware_command', {
				config: {
					firmware_path: firmwarePath.trim(),
					vendor: vendor.trim(),
					model: model.trim(),
					extract_filesystem: extractFilesystem,
					find_credentials: findCredentials,
					analyze_binaries: analyzeBinaries,
					check_backdoors: checkBackdoors,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(firmwarePath.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(firmwarePath.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		firmwarePath = '';
		vendor = '';
		model = '';
		extractFilesystem = true;
		findCredentials = true;
		analyzeBinaries = true;
		checkBackdoors = true;
		result = null;
		error = '';
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
		return `${(bytes / 1073741824).toFixed(1)} GB`;
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
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📦 {$tr('firmwareAnalyzer.title')}</h1>
			<p class="page-subtitle">{$tr('firmwareAnalyzer.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('firmwareAnalyzer.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('firmwareAnalyzer.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('firmwareAnalyzer.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('firmwareAnalyzer.config.title')}</h2>
					<p class="section-desc">{$tr('firmwareAnalyzer.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('firmwareAnalyzer.firmwarePath')}</label>
						<div class="input-with-btn">
							<input type="text" bind:value={firmwarePath} placeholder="/path/to/firmware.bin" class="form-input" disabled={processing} />
							<button class="btn-icon" onclick={selectFirmwareFile} disabled={processing} title="Browse">📁</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('firmwareAnalyzer.vendor')}</label>
						<input type="text" bind:value={vendor} placeholder="e.g. TP-Link, D-Link" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('firmwareAnalyzer.model')}</label>
						<input type="text" bind:value={model} placeholder="e.g. WR841N" class="form-input" disabled={processing} />
					</div>

					<div class="checkbox-group">
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={extractFilesystem} />
							<span>{$tr('firmwareAnalyzer.extractFilesystem')}</span>
						</label>
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={findCredentials} />
							<span>{$tr('firmwareAnalyzer.findCredentials')}</span>
						</label>
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={analyzeBinaries} />
							<span>{$tr('firmwareAnalyzer.analyzeBinaries')}</span>
						</label>
						<label class="checkbox-label">
							<input type="checkbox" bind:checked={checkBackdoors} />
							<span>{$tr('firmwareAnalyzer.checkBackdoors')}</span>
						</label>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !firmwarePath.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('firmwareAnalyzer.analyzing')}{:else}🔍 {$tr('firmwareAnalyzer.analyze')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('firmwareAnalyzer.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('firmwareAnalyzer.title')}</span>
								<span class="query-text">{result.firmware_info.vendor} {result.firmware_info.model}</span>
								<span class="status-badge {result.success ? 'success' : 'failed'}">{result.success ? $tr('firmwareAnalyzer.result.success') : $tr('firmwareAnalyzer.result.failed')}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{result.partitions.length} {$tr('firmwareAnalyzer.result.partitions')}</span>
								<span class="summary-badge red">{result.credentials.length} {$tr('firmwareAnalyzer.result.credentials')}</span>
								{#if highFindingCount > 0}
									<span class="summary-badge orange">{highFindingCount} {$tr('firmwareAnalyzer.result.highFindings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value purple">{result.partitions.length}</div>
								<div class="stat-label">{$tr('firmwareAnalyzer.result.partitions')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{result.credentials.length}</div>
								<div class="stat-label">{$tr('firmwareAnalyzer.result.credentials')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value blue">{result.binaries.length}</div>
								<div class="stat-label">{$tr('firmwareAnalyzer.result.binaries')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value orange">{result.backdoors.length}</div>
								<div class="stat-label">{$tr('firmwareAnalyzer.result.backdoors')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value yellow">{highFindingCount}</div>
								<div class="stat-label">{$tr('firmwareAnalyzer.result.highFindings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('firmwareAnalyzer.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'info' ? 'active' : ''}" onclick={() => activeResultTab = 'info'}>{$tr('firmwareAnalyzer.tabs.info')}</button>
							<button class="result-tab {activeResultTab === 'partitions' ? 'active' : ''}" onclick={() => activeResultTab = 'partitions'}>{$tr('firmwareAnalyzer.tabs.partitions')} ({result.partitions.length})</button>
							<button class="result-tab {activeResultTab === 'credentials' ? 'active' : ''}" onclick={() => activeResultTab = 'credentials'}>{$tr('firmwareAnalyzer.tabs.credentials')} ({result.credentials.length})</button>
							<button class="result-tab {activeResultTab === 'binaries' ? 'active' : ''}" onclick={() => activeResultTab = 'binaries'}>{$tr('firmwareAnalyzer.tabs.binaries')} ({result.binaries.length})</button>
							<button class="result-tab {activeResultTab === 'backdoors' ? 'active' : ''}" onclick={() => activeResultTab = 'backdoors'}>{$tr('firmwareAnalyzer.tabs.backdoors')} ({result.backdoors.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('firmwareAnalyzer.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if result.security_findings.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('firmwareAnalyzer.result.securityFindings')} ({result.security_findings.length})</h3>
										<div class="detection-list">
											{#each result.security_findings as finding}
												<div class="detection-item">
													<div class="detection-header">
														<span class="detection-family">{translateCategory(finding.category)}</span>
														<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
													</div>
													<p class="detection-desc">{finding.description}</p>
													<p class="detection-rec">💡 {$tr('firmwareAnalyzer.result.recommendation')}: {finding.recommendation}</p>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.credentials.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('firmwareAnalyzer.result.credentials')} ({result.credentials.length})</h3>
										<div class="tag-grid">
											{#each result.credentials as cred}
												<span class="tag-item red">
													{cred.credential_type}: {cred.username}
												</span>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.backdoors.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('firmwareAnalyzer.result.backdoors')} ({result.backdoors.length})</h3>
										<div class="detection-list">
											{#each result.backdoors as bd}
												<div class="detection-card" style="border-left-color: {getSeverityBorder(bd.severity)}; background: {getSeverityBg(bd.severity)};">
													<div class="detection-header">
														<h4 class="detection-family">{bd.backdoor_type}</h4>
														<span class="severity-badge large" style="background: {getSeverityBorder(bd.severity)}; color: {getSeverityColor(bd.severity)};">{translateSeverity(bd.severity)}</span>
													</div>
													<p class="detection-desc">{bd.description}</p>
													<div class="tag-grid" style="margin-top: 0.4rem;">
														{#each bd.indicators as ind}
															<span class="tag-item gray">{ind}</span>
														{/each}
													</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'info'}
							<div class="info-grid">
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.vendor')}</span>
									<span class="info-value">{result.firmware_info.vendor}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.model')}</span>
									<span class="info-value">{result.firmware_info.model}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.version')}</span>
									<span class="info-value">{result.firmware_info.version}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.architecture')}</span>
									<span class="info-value">{result.firmware_info.architecture}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.fileSize')}</span>
									<span class="info-value">{formatSize(result.firmware_info.file_size)}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.fileType')}</span>
									<span class="info-value">{result.firmware_info.file_type}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.checksum')}</span>
									<span class="info-value mono-text">{result.firmware_info.checksum}</span>
								</div>
								<div class="info-item">
									<span class="info-label">{$tr('firmwareAnalyzer.table.buildDate')}</span>
									<span class="info-value">{result.firmware_info.build_date || $tr('firmwareAnalyzer.table.unknown')}</span>
								</div>
							</div>
						{:else if activeResultTab === 'partitions'}
							{#if result.partitions.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('firmwareAnalyzer.table.name')}</th>
												<th>{$tr('firmwareAnalyzer.table.offset')}</th>
												<th>{$tr('firmwareAnalyzer.table.size')}</th>
												<th>{$tr('firmwareAnalyzer.table.fileSystem')}</th>
												<th>{$tr('firmwareAnalyzer.table.readable')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.partitions as part}
												<tr>
													<td class="device-name">{part.name}</td>
													<td class="mono-text">0x{part.offset.toString(16)}</td>
													<td>{formatSize(part.size)}</td>
													<td><span class="tag-item gray">{part.file_system}</span></td>
													<td>
														{#if part.is_readable}
															<span class="state-tag active">✓</span>
														{:else}
															<span class="state-tag suspicious">✗</span>
														{/if}
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('firmwareAnalyzer.result.noPartitions')}</div>
							{/if}
						{:else if activeResultTab === 'credentials'}
							{#if result.credentials.length > 0}
								<div class="detection-list">
									{#each result.credentials as cred}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(cred.severity)}; background: {getSeverityBg(cred.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{cred.credential_type}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(cred.severity)}; color: {getSeverityColor(cred.severity)};">{translateSeverity(cred.severity)}</span>
											</div>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.username')}:</span> <span class="mono-text">{cred.username}</span></span>
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.password')}:</span> <span class="mono-text cred-password">{cred.password}</span></span>
											</div>
											<div class="detection-meta" style="margin-top: 0.2rem;">
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.location')}:</span> <span class="mono-text">{cred.location}</span></span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('firmwareAnalyzer.result.noCredentials')}</div>
							{/if}
						{:else if activeResultTab === 'binaries'}
							{#if result.binaries.length > 0}
								<div class="detection-list">
									{#each result.binaries as bin}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(bin.severity)}; background: {getSeverityBg(bin.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{bin.name}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(bin.severity)}; color: {getSeverityColor(bin.severity)};">{translateSeverity(bin.severity)}</span>
											</div>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.path')}:</span> <span class="mono-text">{bin.path}</span></span>
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.architecture')}:</span> {bin.architecture}</span>
											</div>
											<div class="detection-meta" style="margin-top: 0.2rem;">
												<span class="meta-item">
													<span class="meta-label">{$tr('firmwareAnalyzer.table.stripped')}:</span>
													{#if bin.is_stripped}<span class="state-tag suspicious">✗</span>{:else}<span class="state-tag active">✓</span>{/if}
												</span>
												<span class="meta-item">
													<span class="meta-label">{$tr('firmwareAnalyzer.table.stackCanary')}:</span>
													{#if bin.has_stack_canary}<span class="state-tag active">✓</span>{:else}<span class="state-tag suspicious">✗</span>{/if}
												</span>
												<span class="meta-item">
													<span class="meta-label">{$tr('firmwareAnalyzer.table.nx')}:</span>
													{#if bin.has_nx}<span class="state-tag active">✓</span>{:else}<span class="state-tag suspicious">✗</span>{/if}
												</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('firmwareAnalyzer.result.noBinaries')}</div>
							{/if}
						{:else if activeResultTab === 'backdoors'}
							{#if result.backdoors.length > 0}
								<div class="detection-list">
									{#each result.backdoors as bd}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(bd.severity)}; background: {getSeverityBg(bd.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{bd.backdoor_type}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(bd.severity)}; color: {getSeverityColor(bd.severity)};">{translateSeverity(bd.severity)}</span>
											</div>
											<p class="detection-desc">{bd.description}</p>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('firmwareAnalyzer.table.location')}:</span> <span class="mono-text">{bd.location}</span></span>
											</div>
											{#if bd.indicators.length > 0}
												<div class="tag-grid" style="margin-top: 0.4rem;">
													{#each bd.indicators as ind}
														<span class="tag-item gray">{ind}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('firmwareAnalyzer.result.noBackdoors')}</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if result.security_findings.length > 0}
								<div class="finding-list">
									{#each result.security_findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)}; border-left: 3px solid;">
											<div class="finding-header">
												<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
												<span class="finding-category">{translateCategory(finding.category)}</span>
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">💡 {$tr('firmwareAnalyzer.result.recommendation')}: {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('firmwareAnalyzer.result.noFindings')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📦</div>
							<p>{$tr('firmwareAnalyzer.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="firmware_analyzer" toolName={$tr('firmwareAnalyzer.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="firmware_analyzer" />
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

	.input-with-btn { display: flex; gap: 0.4rem; }
	.input-with-btn .form-input { flex: 1; }
	.btn-icon { padding: 0.55rem 0.7rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #94a3b8; cursor: pointer; transition: all 0.2s; font-size: 0.85rem; }
	.btn-icon:hover:not(:disabled) { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border-color: rgba(168, 85, 247, 0.3); }
	.btn-icon:disabled { opacity: 0.5; cursor: not-allowed; }

	.checkbox-group { display: flex; flex-direction: column; gap: 0.5rem; margin: 0.75rem 0; }
	.checkbox-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #cbd5e1; cursor: pointer; }
	.checkbox-label input[type="checkbox"] { accent-color: #a855f7; }

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

	.summary-banner { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
	.summary-info { display: flex; align-items: center; gap: 0.75rem; }
	.domain-badge { padding: 0.2rem 0.6rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 0.3rem; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.05em; }
	.query-text { font-size: 0.85rem; color: #f1f5f9; font-weight: 500; font-family: 'SF Mono', 'Fira Code', monospace; }
	.status-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; }
	.status-badge.success { background: rgba(34, 197, 94, 0.15); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
	.status-badge.failed { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
	.summary-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.summary-badge { padding: 0.25rem 0.6rem; border-radius: 0.4rem; font-size: 0.75rem; font-weight: 600; }
	.summary-badge.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
	.summary-badge.orange { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }

	.stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.stat-card { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-value.purple { color: #c4b5fd; }
	.stat-value.orange { color: #fdba74; }
	.stat-value.blue { color: #93c5fd; }
	.stat-value.red { color: #fca5a5; }
	.stat-value.yellow { color: #fbbf24; }
	.stat-label { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.items-list { display: flex; flex-direction: column; gap: 1rem; }
	.item-section-title { font-size: 0.85rem; font-weight: 600; color: #c4b5fd; margin: 0 0 0.5rem; }

	.tag-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
	.tag-item { padding: 0.25rem 0.6rem; border-radius: 0.3rem; font-size: 0.75rem; font-weight: 500; }
	.tag-item.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.2); }
	.tag-item.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }

	.detection-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.detection-item { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.detection-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; border-left: 3px solid rgba(168, 85, 247, 0.5); }
	.detection-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; flex-wrap: wrap; gap: 0.3rem; }
	.detection-family { font-weight: 600; color: #c4b5fd; font-size: 0.9rem; }
	.detection-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0 0; }
	.detection-rec { font-size: 0.8rem; color: #86efac; margin: 0.3rem 0 0; }
	.detection-meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.meta-item { font-size: 0.85rem; color: #cbd5e1; }
	.meta-label { color: #94a3b8; margin-right: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.severity-badge.large { font-size: 0.8rem; padding: 0.2rem 0.6rem; }

	.info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem; }
	.info-item { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; padding: 0.75rem; }
	.info-label { display: block; font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.3rem; }
	.info-value { font-size: 0.9rem; color: #f1f5f9; font-weight: 500; }

	.table-wrapper { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { padding: 0.5rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.mono-text { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #93c5fd; }
	.device-name { font-weight: 500; color: #f1f5f9; }
	.cred-password { color: #fca5a5; }

	.state-tag { padding: 0.1rem 0.4rem; border-radius: 0.2rem; font-size: 0.75rem; background: rgba(148, 163, 184, 0.1); }
	.state-tag.active { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.state-tag.suspicious { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }

	.finding-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.finding-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
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
		.info-grid { grid-template-columns: 1fr; }
	}
</style>
