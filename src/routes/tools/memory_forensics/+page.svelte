<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface MemoryProcess {
		pid: number;
		ppid: number;
		name: string;
		full_path: string;
		command_line: string;
		is_suspicious: boolean;
		suspicion_reasons: string[];
	}

	interface MemoryConnection {
		local_address: string;
		remote_address: string;
		state: string;
		protocol: string;
		pid: number;
		process_name: string;
		is_suspicious: boolean;
	}

	interface MemoryArtifact {
		artifact_type: string;
		name: string;
		description: string;
		location: string;
		severity: string;
		indicators: string[];
	}

	interface InjectedCode {
		pid: number;
		process_name: string;
		injection_type: string;
		base_address: string;
		size: number;
		severity: string;
	}

	interface RegistryKey {
		key_path: string;
		value_name: string;
		value_data: string;
		is_suspicious: boolean;
		category: string;
	}

	interface MemorySecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		mitre_technique: string | null;
	}

	interface MemoryForensicsResult {
		success: boolean;
		analysis_type: string;
		processes: MemoryProcess[];
		connections: MemoryConnection[];
		artifacts: MemoryArtifact[];
		injected_code: InjectedCode[];
		registry_keys: RegistryKey[];
		security_findings: MemorySecurityFinding[];
		summary: string;
	}

	let dumpPath = $state('');
	let profile = $state('auto');
	let analysisType = $state('full');
	let result: MemoryForensicsResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory = $state(null!);

	let highFindingCount = $derived(
		(result as MemoryForensicsResult | null)?.security_findings.filter((f: MemorySecurityFinding) => f.severity === 'critical' || f.severity === 'high').length ?? 0
	);

	function translateSeverity(sev: string): string {
		const key = `memoryForensics.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	function translateCategory(cat: string): string {
		const key = `memoryForensics.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	async function selectDumpFile() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				multiple: false,
				title: $tr('memoryForensics.dumpPath'),
				filters: [{
					name: 'Memory Dump',
					extensions: ['dmp', 'dump', 'raw', 'vmem', 'lime', 'elf', 'bin']
				}]
			});
			if (selected) {
				dumpPath = typeof selected === 'string' ? selected : (selected as any).path || String(selected);
			}
		} catch (e) {
			console.error('File dialog failed:', e);
		}
	}

	async function analyze() {
		if (!dumpPath.trim()) {
			error = $tr('memoryForensics.error.noPath');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<MemoryForensicsResult>('analyze_memory_command', {
				config: {
					dump_path: dumpPath.trim(),
					profile,
					analysis_type: analysisType,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					dumpPath.trim(),
					JSON.stringify(result),
					result.summary,
					'completed'
				);
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(dumpPath.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		dumpPath = '';
		profile = 'auto';
		analysisType = 'full';
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
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">💾 {$tr('memoryForensics.title')}</h1>
			<p class="page-subtitle">{$tr('memoryForensics.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('memoryForensics.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('memoryForensics.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('memoryForensics.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('memoryForensics.config.title')}</h2>
					<p class="section-desc">{$tr('memoryForensics.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('memoryForensics.dumpPath')}</label>
						<div class="input-with-btn">
							<input type="text" bind:value={dumpPath} placeholder="/path/to/memory.dmp" class="form-input" disabled={processing} />
							<button class="btn-icon" onclick={selectDumpFile} disabled={processing} title="Browse">📁</button>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('memoryForensics.profile')}</label>
						<select bind:value={profile} class="form-input" disabled={processing}>
							<option value="auto">{$tr('memoryForensics.profileAuto')}</option>
							<option value="win10">Windows 10</option>
							<option value="win7">Windows 7</option>
							<option value="linux">Linux</option>
							<option value="macos">macOS</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('memoryForensics.analysisType')}</label>
						<select bind:value={analysisType} class="form-input" disabled={processing}>
							<option value="full">{$tr('memoryForensics.full')}</option>
							<option value="processes">{$tr('memoryForensics.processes')}</option>
							<option value="network">{$tr('memoryForensics.network')}</option>
							<option value="malware">{$tr('memoryForensics.malware')}</option>
							<option value="persistence">{$tr('memoryForensics.persistence')}</option>
						</select>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !dumpPath.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('memoryForensics.analyzing')}{:else}🔍 {$tr('memoryForensics.analyze')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('memoryForensics.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('memoryForensics.analysisType')}</span>
								<span class="query-text">{result.analysis_type.toUpperCase()}</span>
								<span class="status-badge {result.success ? 'success' : 'failed'}">{result.success ? $tr('memoryForensics.result.success') : $tr('memoryForensics.result.failed')}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{result.processes.length} {$tr('memoryForensics.result.processes')}</span>
								<span class="summary-badge orange">{result.artifacts.length} {$tr('memoryForensics.result.artifacts')}</span>
								{#if highFindingCount > 0}
									<span class="summary-badge red">{highFindingCount} {$tr('memoryForensics.result.highFindings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value purple">{result.processes.length}</div>
								<div class="stat-label">{$tr('memoryForensics.result.processes')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value blue">{result.connections.length}</div>
								<div class="stat-label">{$tr('memoryForensics.result.connections')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value orange">{result.artifacts.length}</div>
								<div class="stat-label">{$tr('memoryForensics.result.artifacts')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{result.injected_code.length}</div>
								<div class="stat-label">{$tr('memoryForensics.result.injectedCode')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value yellow">{highFindingCount}</div>
								<div class="stat-label">{$tr('memoryForensics.result.highFindings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('memoryForensics.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'processes' ? 'active' : ''}" onclick={() => activeResultTab = 'processes'}>{$tr('memoryForensics.tabs.processes')} ({result.processes.length})</button>
							<button class="result-tab {activeResultTab === 'connections' ? 'active' : ''}" onclick={() => activeResultTab = 'connections'}>{$tr('memoryForensics.tabs.connections')} ({result.connections.length})</button>
							<button class="result-tab {activeResultTab === 'artifacts' ? 'active' : ''}" onclick={() => activeResultTab = 'artifacts'}>{$tr('memoryForensics.tabs.artifacts')} ({result.artifacts.length})</button>
							<button class="result-tab {activeResultTab === 'injected' ? 'active' : ''}" onclick={() => activeResultTab = 'injected'}>{$tr('memoryForensics.tabs.injected')} ({result.injected_code.length})</button>
							<button class="result-tab {activeResultTab === 'registry' ? 'active' : ''}" onclick={() => activeResultTab = 'registry'}>{$tr('memoryForensics.tabs.registry')} ({result.registry_keys.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('memoryForensics.tabs.findings')} ({result.security_findings.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if result.security_findings.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('memoryForensics.result.securityFindings')} ({result.security_findings.length})</h3>
										<div class="detection-list">
											{#each result.security_findings as finding}
												<div class="detection-item">
													<div class="detection-header">
														<span class="detection-family">{translateCategory(finding.category)}</span>
														<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
													</div>
													<p class="detection-desc">{finding.description}</p>
													{#if finding.mitre_technique}
														<span class="mitre-tag">{finding.mitre_technique}</span>
													{/if}
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.processes.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('memoryForensics.result.processes')} ({result.processes.length})</h3>
										<div class="tag-grid">
											{#each result.processes.filter(p => p.is_suspicious).concat(result.processes.filter(p => !p.is_suspicious)).slice(0, 20) as proc}
												<span class="tag-item {proc.is_suspicious ? 'red' : 'purple'}">
													{proc.name}
													<span class="process-tag">(PID: {proc.pid})</span>
												</span>
											{/each}
										</div>
									</div>
								{/if}

								{#if result.injected_code.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('memoryForensics.result.injectedCode')} ({result.injected_code.length})</h3>
										<div class="detection-list">
											{#each result.injected_code as inj}
												<div class="detection-card" style="border-left-color: {getSeverityBorder(inj.severity)}; background: {getSeverityBg(inj.severity)};">
													<div class="detection-header">
														<h4 class="detection-family">{inj.process_name} (PID: {inj.pid})</h4>
														<span class="severity-badge large" style="background: {getSeverityBorder(inj.severity)}; color: {getSeverityColor(inj.severity)};">{translateSeverity(inj.severity)}</span>
													</div>
													<div class="detection-meta">
														<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.injectionType')}:</span> {inj.injection_type}</span>
														<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.baseAddress')}:</span> <span class="mono-text">{inj.base_address}</span></span>
														<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.size')}:</span> {inj.size} bytes</span>
													</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'processes'}
							{#if result.processes.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>PID</th>
												<th>PPID</th>
												<th>{$tr('memoryForensics.table.processName')}</th>
												<th>{$tr('memoryForensics.table.path')}</th>
												<th>{$tr('memoryForensics.table.status')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.processes as proc}
												<tr>
													<td class="mono-text">{proc.pid}</td>
													<td class="mono-text">{proc.ppid}</td>
													<td class="device-name">{proc.name}</td>
													<td class="mono-text" style="font-size: 0.78rem;">{proc.full_path}</td>
													<td>
														{#if proc.is_suspicious}
															<span class="state-tag suspicious">⚠️ {$tr('memoryForensics.suspicious')}</span>
														{:else}
															<span class="state-tag active">✓</span>
														{/if}
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noProcesses')}</div>
							{/if}
						{:else if activeResultTab === 'connections'}
							{#if result.connections.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('memoryForensics.table.localAddress')}</th>
												<th>{$tr('memoryForensics.table.remoteAddress')}</th>
												<th>{$tr('memoryForensics.table.protocol')}</th>
												<th>{$tr('memoryForensics.table.state')}</th>
												<th>{$tr('memoryForensics.table.process')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.connections as conn}
												<tr>
													<td class="mono-text">{conn.local_address}</td>
													<td class="mono-text" style="color: {conn.is_suspicious ? '#fca5a5' : '#93c5fd'};">{conn.remote_address}</td>
													<td>{conn.protocol}</td>
													<td>{conn.state}</td>
													<td>{conn.process_name} <span class="process-tag">(PID: {conn.pid})</span></td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noConnections')}</div>
							{/if}
						{:else if activeResultTab === 'artifacts'}
							{#if result.artifacts.length > 0}
								<div class="detection-list">
									{#each result.artifacts as artifact}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(artifact.severity)}; background: {getSeverityBg(artifact.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{artifact.artifact_type}: {artifact.name}</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(artifact.severity)}; color: {getSeverityColor(artifact.severity)};">{translateSeverity(artifact.severity)}</span>
											</div>
											<p class="detection-desc">{artifact.description}</p>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.location')}:</span> <span class="mono-text">{artifact.location}</span></span>
											</div>
											{#if artifact.indicators.length > 0}
												<div class="tag-grid" style="margin-top: 0.4rem;">
													{#each artifact.indicators as ind}
														<span class="tag-item gray">{ind}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noArtifacts')}</div>
							{/if}
						{:else if activeResultTab === 'injected'}
							{#if result.injected_code.length > 0}
								<div class="detection-list">
									{#each result.injected_code as inj}
										<div class="detection-card" style="border-left-color: {getSeverityBorder(inj.severity)}; background: {getSeverityBg(inj.severity)};">
											<div class="detection-header">
												<h4 class="detection-family">{inj.process_name} (PID: {inj.pid})</h4>
												<span class="severity-badge large" style="background: {getSeverityBorder(inj.severity)}; color: {getSeverityColor(inj.severity)};">{translateSeverity(inj.severity)}</span>
											</div>
											<div class="detection-meta">
												<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.injectionType')}:</span> {inj.injection_type}</span>
												<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.baseAddress')}:</span> <span class="mono-text">{inj.base_address}</span></span>
												<span class="meta-item"><span class="meta-label">{$tr('memoryForensics.table.size')}:</span> {inj.size} bytes</span>
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noInjected')}</div>
							{/if}
						{:else if activeResultTab === 'registry'}
							{#if result.registry_keys.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('memoryForensics.table.keyPath')}</th>
												<th>{$tr('memoryForensics.table.valueName')}</th>
												<th>{$tr('memoryForensics.table.category')}</th>
												<th>{$tr('memoryForensics.table.status')}</th>
											</tr>
										</thead>
										<tbody>
											{#each result.registry_keys as key}
												<tr>
													<td class="mono-text" style="font-size: 0.78rem;">{key.key_path}</td>
													<td>{key.value_name}</td>
													<td><span class="tag-item gray">{key.category}</span></td>
													<td>
														{#if key.is_suspicious}
															<span class="state-tag suspicious">⚠️ {$tr('memoryForensics.suspicious')}</span>
														{:else}
															<span class="state-tag active">✓</span>
														{/if}
													</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noRegistry')}</div>
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
											<p class="finding-rec">💡 {$tr('memoryForensics.result.recommendation')}: {finding.recommendation}</p>
											{#if finding.mitre_technique}
												<span class="mitre-tag">MITRE: {finding.mitre_technique}</span>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('memoryForensics.result.noFindings')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">💾</div>
							<p>{$tr('memoryForensics.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="memory_forensics" toolName={$tr('memoryForensics.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="memory_forensics" />
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
	.summary-badge.orange { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
	.summary-badge.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

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
	.tag-item.purple { background: rgba(168, 85, 247, 0.15); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.2); }
	.tag-item.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.2); }
	.tag-item.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }
	.process-tag { opacity: 0.7; font-size: 0.7rem; margin-left: 0.3rem; }

	.detection-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.detection-item { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.detection-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(249, 115, 22, 0.15); border-radius: 0.5rem; border-left: 3px solid rgba(249, 115, 22, 0.5); }
	.detection-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; flex-wrap: wrap; gap: 0.3rem; }
	.detection-family { font-weight: 600; color: #fdba74; font-size: 0.9rem; }
	.detection-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0 0; }
	.detection-meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; color: #94a3b8; margin-top: 0.3rem; }
	.meta-item { font-size: 0.85rem; color: #cbd5e1; }
	.meta-label { color: #94a3b8; margin-right: 0.3rem; }

	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.severity-badge.large { font-size: 0.8rem; padding: 0.2rem 0.6rem; }

	.mitre-tag { font-size: 0.7rem; color: #c4b5fd; background: rgba(168, 85, 247, 0.1); padding: 0.1rem 0.4rem; border-radius: 0.2rem; border: 1px solid rgba(168, 85, 247, 0.2); margin-top: 0.3rem; display: inline-block; }

	.table-wrapper { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { padding: 0.5rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.mono-text { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #93c5fd; }
	.device-name { font-weight: 500; color: #f1f5f9; }

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
	}
</style>
