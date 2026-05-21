<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface RatConnection {
		remote_address: string;
		local_address: string;
		state: string;
		protocol: string;
		process_name: string;
		pid: number;
		data_volume: number;
		duration_secs: number;
		is_suspicious: boolean;
	}

	interface RatCapability {
		name: string;
		category: string;
		risk_level: string;
		description: string;
		indicators: string[];
	}

	interface RatDetection {
		rat_family: string;
		confidence: number;
		indicators: string[];
		c2_server: string;
		protocol: string;
		persistence_mechanism: string;
	}

	interface RatSecurityFinding {
		severity: string;
		category: string;
		description: string;
		recommendation: string;
		mitre_technique: string | null;
	}

	interface RatToolResult {
		success: boolean;
		target: string;
		connections: RatConnection[];
		capabilities: RatCapability[];
		detections: RatDetection[];
		security_findings: RatSecurityFinding[];
		summary: string;
	}

	let targetHost = $state('');
	let targetPort = $state(4444);
	let protocol = $state('tcp');
	let operation = $state('detect');
	let result: RatToolResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');

	let historyComponent: ToolHistory;

	let highFindingCount = $derived(
		result ? (result as RatToolResult).security_findings.filter(f => f.severity === 'critical' || f.severity === 'high').length : 0
	);

	function translateCategory(cat: string): string {
		const key = `ratTool.category.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	function translateSeverity(sev: string): string {
		const key = `ratTool.severity.${sev}`;
		const val = $tr(key);
		return val === key ? sev : val;
	}

	function translateCapabilityCategory(cat: string): string {
		const key = `ratTool.capCategory.${cat}`;
		const val = $tr(key);
		return val === key ? cat : val;
	}

	async function analyze() {
		if (!targetHost.trim()) {
			error = $tr('ratTool.error.hostRequired');
			return;
		}
		processing = true;
		error = '';
		result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<RatToolResult>('analyze_rat_command', {
				config: {
					target_host: targetHost.trim(),
					target_port: targetPort,
					protocol,
					operation,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(targetHost.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(targetHost.trim(), '', error, 'failed');
			}
		} finally {
			processing = false;
		}
	}

	function clearAll() {
		targetHost = '';
		targetPort = 4444;
		protocol = 'tcp';
		operation = 'detect';
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

	function getConfidencePercent(confidence: number): string {
		return (confidence * 100).toFixed(0) + '%';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🖥️ {$tr('ratTool.title')}</h1>
			<p class="page-subtitle">{$tr('ratTool.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('ratTool.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('ratTool.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('ratTool.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('ratTool.config.title')}</h2>
					<p class="section-desc">{$tr('ratTool.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('ratTool.targetHost')}</label>
						<input type="text" bind:value={targetHost} placeholder={$tr('ratTool.config.hostPlaceholder')} class="form-input" disabled={processing} onkeydown={(e) => e.key === 'Enter' && analyze()} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('ratTool.targetPort')}</label>
						<input type="number" bind:value={targetPort} min="1" max="65535" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('ratTool.protocol')}</label>
						<select bind:value={protocol} class="form-input" disabled={processing}>
							<option value="tcp">TCP</option>
							<option value="udp">UDP</option>
							<option value="http">HTTP</option>
							<option value="https">HTTPS</option>
							<option value="dns">DNS</option>
						</select>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('ratTool.operation')}</label>
						<select bind:value={operation} class="form-input" disabled={processing}>
							<option value="detect">{$tr('ratTool.detect')}</option>
							<option value="capabilities">{$tr('ratTool.capabilities')}</option>
							<option value="full">{$tr('ratTool.fullAudit')}</option>
						</select>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing}>
							{#if processing}<span class="spinner"></span> {$tr('ratTool.analyzing')}{:else}🔍 {$tr('ratTool.start')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('ratTool.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-text">{error}</div>
						</div>
					{:else if result}
						<div class="summary-banner">
							<div class="summary-info">
								<span class="domain-badge">{$tr('ratTool.target')}</span>
								<span class="query-text">{(result as RatToolResult).target}</span>
								<span class="status-badge {(result as RatToolResult).success ? 'success' : 'failed'}">{(result as RatToolResult).success ? $tr('ratTool.result.success') : $tr('ratTool.result.failed')}</span>
							</div>
							<div class="summary-badges">
								<span class="summary-badge purple">{(result as RatToolResult).connections.length} {$tr('ratTool.result.connections')}</span>
								<span class="summary-badge orange">{(result as RatToolResult).detections.length} {$tr('ratTool.result.detections')}</span>
								{#if highFindingCount > 0}
									<span class="summary-badge red">{highFindingCount} {$tr('ratTool.result.highFindings')}</span>
								{/if}
							</div>
						</div>

						<div class="stats-grid">
							<div class="stat-card">
								<div class="stat-value orange">{(result as RatToolResult).detections.length}</div>
								<div class="stat-label">{$tr('ratTool.result.detections')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value purple">{(result as RatToolResult).connections.length}</div>
								<div class="stat-label">{$tr('ratTool.result.connections')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value blue">{(result as RatToolResult).capabilities.length}</div>
								<div class="stat-label">{$tr('ratTool.result.capabilities')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value red">{highFindingCount}</div>
								<div class="stat-label">{$tr('ratTool.result.highFindings')}</div>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>{$tr('ratTool.tabs.overview')}</button>
							<button class="result-tab {activeResultTab === 'connections' ? 'active' : ''}" onclick={() => activeResultTab = 'connections'}>{$tr('ratTool.tabs.connections')} ({(result as RatToolResult).connections.length})</button>
							<button class="result-tab {activeResultTab === 'detections' ? 'active' : ''}" onclick={() => activeResultTab = 'detections'}>{$tr('ratTool.tabs.detections')} ({(result as RatToolResult).detections.length})</button>
							<button class="result-tab {activeResultTab === 'capabilities' ? 'active' : ''}" onclick={() => activeResultTab = 'capabilities'}>{$tr('ratTool.tabs.capabilities')} ({(result as RatToolResult).capabilities.length})</button>
							<button class="result-tab {activeResultTab === 'findings' ? 'active' : ''}" onclick={() => activeResultTab = 'findings'}>{$tr('ratTool.tabs.findings')} ({(result as RatToolResult).security_findings.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="items-list">
								{#if (result as RatToolResult).detections.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('ratTool.result.detections')} ({(result as RatToolResult).detections.length})</h3>
										<div class="detection-list">
											{#each (result as RatToolResult).detections as det}
												<div class="detection-item">
													<div class="detection-header">
														<span class="detection-family">{det.rat_family}</span>
														<span class="confidence-badge">{getConfidencePercent(det.confidence)}</span>
													</div>
													<div class="detection-meta">
														<span class="meta-item"><span class="meta-label">C2:</span> <span class="mono-text">{det.c2_server}</span></span>
														<span class="meta-item"><span class="meta-label">{$tr('ratTool.result.protocol')}:</span> {det.protocol}</span>
													</div>
													{#if det.indicators.length > 0}
														<div class="tag-grid">
															{#each det.indicators as ind}
																<span class="tag-item orange">{ind}</span>
															{/each}
														</div>
													{/if}
												</div>
											{/each}
										</div>
									</div>
								{/if}

								{#if (result as RatToolResult).connections.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('ratTool.result.suspiciousConnections')} ({(result as RatToolResult).connections.filter(c => c.is_suspicious).length})</h3>
										<div class="tag-grid">
											{#each (result as RatToolResult).connections.filter(c => c.is_suspicious) as conn}
												<span class="tag-item red">
													{conn.remote_address}
													{#if conn.process_name && conn.process_name !== 'unknown'}<span class="process-tag">({conn.process_name})</span>{/if}
												</span>
											{/each}
										</div>
									</div>
								{/if}

								{#if (result as RatToolResult).security_findings.length > 0}
									<div>
										<h3 class="item-section-title">{$tr('ratTool.result.securityFindings')} ({(result as RatToolResult).security_findings.length})</h3>
										<div class="finding-list">
											{#each (result as RatToolResult).security_findings as finding}
												<div class="finding-item" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
													<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
													<span class="finding-category">{translateCategory(finding.category)}</span>
												</div>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'connections'}
							{#if (result as RatToolResult).connections.length > 0}
								<div class="table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('ratTool.table.remoteAddress')}</th>
												<th>{$tr('ratTool.table.protocol')}</th>
												<th>{$tr('ratTool.table.process')}</th>
												<th>{$tr('ratTool.table.state')}</th>
												<th>{$tr('ratTool.table.suspicious')}</th>
											</tr>
										</thead>
										<tbody>
											{#each (result as RatToolResult).connections as conn}
												<tr>
													<td class="mono-text">{conn.remote_address}</td>
													<td>{conn.protocol}</td>
													<td>{conn.process_name} {#if conn.pid > 0}<span class="pid-tag">PID:{conn.pid}</span>{/if}</td>
													<td><span class="state-tag {conn.state === 'ESTABLISHED' ? 'active' : ''}">{conn.state}</span></td>
													<td>{#if conn.is_suspicious}<span class="suspicious-mark">⚠️</span>{:else}<span class="safe-mark">✓</span>{/if}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{:else}
								<div class="empty-item">{$tr('ratTool.result.noConnections')}</div>
							{/if}
						{:else if activeResultTab === 'detections'}
							{#if (result as RatToolResult).detections.length > 0}
								<div class="detection-list">
									{#each (result as RatToolResult).detections as det}
										<div class="detection-card">
											<div class="detection-header">
												<h4 class="detection-family">{det.rat_family}</h4>
												<span class="confidence-badge large">{getConfidencePercent(det.confidence)}</span>
											</div>
											<div class="detection-details">
												<div class="detail-row">
													<span class="detail-label">C2 {$tr('ratTool.result.server')}:</span>
													<span class="mono-text">{det.c2_server}</span>
												</div>
												<div class="detail-row">
													<span class="detail-label">{$tr('ratTool.result.protocol')}:</span>
													<span>{det.protocol}</span>
												</div>
												<div class="detail-row">
													<span class="detail-label">{$tr('ratTool.result.persistence')}:</span>
													<span>{det.persistence_mechanism}</span>
												</div>
											</div>
											{#if det.indicators.length > 0}
												<div class="tag-grid" style="margin-top: 0.5rem;">
													{#each det.indicators as ind}
														<span class="tag-item orange">{ind}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('ratTool.result.noDetections')}</div>
							{/if}
						{:else if activeResultTab === 'capabilities'}
							{#if (result as RatToolResult).capabilities.length > 0}
								<div class="capability-list">
									{#each (result as RatToolResult).capabilities as cap}
										<div class="capability-card" style="border-left-color: {getSeverityBorder(cap.risk_level)}; background: {getSeverityBg(cap.risk_level)};">
											<div class="capability-header">
												<span class="capability-name">{cap.name}</span>
												<span class="severity-badge" style="background: {getSeverityBorder(cap.risk_level)}; color: {getSeverityColor(cap.risk_level)};">{translateSeverity(cap.risk_level)}</span>
											</div>
											<div class="capability-meta">
												<span class="cap-category">{translateCapabilityCategory(cap.category)}</span>
											</div>
											<p class="capability-desc">{cap.description}</p>
											{#if cap.indicators.length > 0}
												<div class="tag-grid" style="margin-top: 0.4rem;">
													{#each cap.indicators as ind}
														<span class="tag-item gray">{ind}</span>
													{/each}
												</div>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('ratTool.result.noCapabilities')}</div>
							{/if}
						{:else if activeResultTab === 'findings'}
							{#if (result as RatToolResult).security_findings.length > 0}
								<div class="finding-list">
									{#each (result as RatToolResult).security_findings as finding}
										<div class="finding-card" style="border-left-color: {getSeverityBorder(finding.severity)}; background: {getSeverityBg(finding.severity)};">
											<div class="finding-header">
												<span class="severity-badge" style="background: {getSeverityBorder(finding.severity)}; color: {getSeverityColor(finding.severity)};">{translateSeverity(finding.severity)}</span>
												<span class="finding-category">{translateCategory(finding.category)}</span>
												{#if finding.mitre_technique}
													<span class="mitre-tag">MITRE: {finding.mitre_technique}</span>
												{/if}
											</div>
											<p class="finding-desc">{finding.description}</p>
											<p class="finding-rec">💡 {$tr('ratTool.result.recommendation')}: {finding.recommendation}</p>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-item">{$tr('ratTool.result.noFindings')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🖥️</div>
							<p>{$tr('ratTool.result.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<ToolHistory bind:this={historyComponent} toolType="rat_tool" toolName={$tr('ratTool.title')} />
	{:else if activeMainTab === 'help'}
		<ToolHelp toolType="rat_tool" />
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
	.tag-item.orange { background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.2); }
	.tag-item.red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.2); }
	.tag-item.gray { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }
	.process-tag { opacity: 0.7; font-size: 0.7rem; margin-left: 0.3rem; }

	.detection-list { display: flex; flex-direction: column; gap: 0.75rem; }
	.detection-item { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.detection-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(249, 115, 22, 0.15); border-radius: 0.5rem; border-left: 3px solid rgba(249, 115, 22, 0.5); }
	.detection-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; }
	.detection-family { font-weight: 600; color: #fdba74; font-size: 0.9rem; }
	.confidence-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; background: rgba(249, 115, 22, 0.15); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
	.confidence-badge.large { font-size: 0.8rem; padding: 0.2rem 0.6rem; }
	.detection-meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem; }
	.detection-details { display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 0.5rem; }
	.detail-row { font-size: 0.85rem; color: #cbd5e1; }
	.detail-label { color: #94a3b8; margin-right: 0.3rem; }

	.table-wrapper { overflow-x: auto; }
	.data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
	.data-table th { padding: 0.5rem 0.75rem; text-align: left; color: #94a3b8; font-weight: 500; border-bottom: 1px solid rgba(148, 163, 184, 0.15); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
	.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.08); color: #cbd5e1; }
	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }
	.mono-text { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #93c5fd; }
	.pid-tag { font-size: 0.7rem; color: #64748b; margin-left: 0.3rem; }
	.state-tag { padding: 0.1rem 0.4rem; border-radius: 0.2rem; font-size: 0.75rem; background: rgba(148, 163, 184, 0.1); }
	.state-tag.active { background: rgba(34, 197, 94, 0.15); color: #86efac; }
	.suspicious-mark { color: #fca5a5; }
	.safe-mark { color: #86efac; }

	.capability-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.capability-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.capability-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem; }
	.capability-name { font-weight: 600; color: #f1f5f9; font-size: 0.9rem; }
	.capability-meta { margin-bottom: 0.3rem; }
	.cap-category { font-size: 0.75rem; color: #94a3b8; }
	.capability-desc { font-size: 0.85rem; color: #cbd5e1; margin: 0.3rem 0 0; }

	.finding-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.finding-card { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.finding-item { padding: 0.5rem 0.75rem; border-radius: 0.4rem; border-left: 3px solid; display: flex; align-items: center; gap: 0.5rem; }
	.finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; flex-wrap: wrap; }
	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.3rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.finding-category { font-size: 0.85rem; font-weight: 500; color: #f1f5f9; }
	.mitre-tag { font-size: 0.7rem; color: #c4b5fd; background: rgba(168, 85, 247, 0.1); padding: 0.1rem 0.4rem; border-radius: 0.2rem; border: 1px solid rgba(168, 85, 247, 0.2); }
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
