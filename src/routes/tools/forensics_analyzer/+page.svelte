<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SuspiciousFile { path: string; reason: string; size: number; modified_time: string; risk_level: string; mitre_id: string; }
	interface FilesystemInfo { file_system_type: string; total_size: number; used_size: number; file_count: number; hidden_files: number; encrypted_files: number; suspicious_files: SuspiciousFile[]; deleted_recoverable: number; }
	interface ProcessInfo { pid: number; name: string; path: string; user: string; memory_mb: number; suspicious: boolean; reason: string; mitre_id: string; }
	interface NetworkConnection { protocol: string; local_addr: string; remote_addr: string; state: string; process: string; suspicious: boolean; reason: string; }
	interface MemoryAnalysis { process_count: number; suspicious_processes: ProcessInfo[]; injected_dlls: string[]; hidden_processes: string[]; network_connections: NetworkConnection[]; }
	interface TimelineEntry { timestamp: string; event_type: string; description: string; source: string; significance: string; mitre_id: string; }
	interface RegistryEntry { key: string; value: string; data: string; suspicious: boolean; reason: string; }
	interface RegistryInfo { run_keys: RegistryEntry[]; services: RegistryEntry[]; suspicious_entries: RegistryEntry[]; }
	interface AntiForensicsIndicator { technique: string; description: string; detected: boolean; evidence: string; severity: string; mitre_id: string; }

	interface ForensicsAnalyzerResult {
		success: boolean; file_path: string;
		filesystem_info: FilesystemInfo; memory_analysis: MemoryAnalysis;
		timeline: TimelineEntry[]; registry_info: RegistryInfo;
		anti_forensics_indicators: AntiForensicsIndicator[];
		recovered_artifacts: number; total_findings: number;
		critical_findings: number; summary: string;
	}

	let target = $state('');
	let analysisType = $state('full');
	let checkFilesystem = $state(true);
	let checkMemory = $state(true);
	let checkNetwork = $state(true);
	let checkTimeline = $state(true);
	let checkAntiForensics = $state(true);
	let result: ForensicsAnalyzerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('overview');
	let historyComponent: ToolHistory = $state(null!);

	async function analyze() {
		if (!target.trim()) { error = $tr('forensicsAnalyzer.error.targetRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<ForensicsAnalyzerResult>('analyze_forensics_command', {
				config: {
					file_path: target.trim(),
					analyze_filesystem: checkFilesystem,
					analyze_memory: checkMemory,
					analyze_network: checkNetwork,
					analyze_timeline: checkTimeline,
					analyze_registry: false,
					recover_deleted: true,
					extract_metadata: true,
					check_anti_forensics: checkAntiForensics,
					timeout: 60,
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) { await historyComponent.saveHistory(target.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed'); }
		} finally { processing = false; }
	}

	function clearAll() { target = ''; result = null; error = ''; }
	function getRiskColor(r: string): string {
		switch (r) { case 'critical': return '#dc2626'; case 'high': return '#ef4444'; case 'medium': return '#f59e0b'; case 'low': return '#3b82f6'; default: return '#6b7280'; }
	}
	function formatSize(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
	}
	function getAnalysisTypeLabel(type: string): string {
		switch (type) {
			case 'quick': return $tr('forensicsAnalyzer.modeQuick');
			case 'full': return $tr('forensicsAnalyzer.modeFull');
			case 'deep': return $tr('forensicsAnalyzer.modeDeep');
			case 'timeline': return $tr('forensicsAnalyzer.modeTimeline');
			default: return type;
		}
	}
	function applyAnalysisMode(mode: string) {
		analysisType = mode;
		switch (mode) {
			case 'quick':
				checkFilesystem = true; checkMemory = false; checkNetwork = false; checkTimeline = false; checkAntiForensics = false;
				break;
			case 'full':
				checkFilesystem = true; checkMemory = true; checkNetwork = true; checkTimeline = true; checkAntiForensics = true;
				break;
			case 'deep':
				checkFilesystem = true; checkMemory = true; checkNetwork = true; checkTimeline = true; checkAntiForensics = true;
				break;
			case 'timeline':
				checkFilesystem = true; checkMemory = false; checkNetwork = false; checkTimeline = true; checkAntiForensics = false;
				break;
		}
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔬 {$tr('forensicsAnalyzer.title')}</h1>
			<p class="page-subtitle">{$tr('forensicsAnalyzer.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('forensicsAnalyzer.analyze')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('forensicsAnalyzer.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('forensicsAnalyzer.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('forensicsAnalyzer.configTitle')}</h2>
					<p class="section-desc">{$tr('forensicsAnalyzer.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('forensicsAnalyzer.targetPath')}</label>
						<input type="text" bind:value={target} placeholder="/path/to/disk_image or /mnt/evidence" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('forensicsAnalyzer.analysisMode')}</label>
						<div class="mode-grid">
							{#each ['quick', 'full', 'deep', 'timeline'] as mode}
								<button class="mode-btn {analysisType === mode ? 'active' : ''}" onclick={() => applyAnalysisMode(mode)} disabled={processing}>
									<span class="mode-name">{getAnalysisTypeLabel(mode)}</span>
								</button>
							{/each}
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('forensicsAnalyzer.analysisOptions')}</label>
						<div class="target-grid">
							<label class="target-chip {checkFilesystem ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkFilesystem} disabled={processing} />
								<span>📁 {$tr('forensicsAnalyzer.optionFilesystem')}</span>
							</label>
							<label class="target-chip {checkMemory ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkMemory} disabled={processing} />
								<span>⚙️ {$tr('forensicsAnalyzer.optionMemory')}</span>
							</label>
							<label class="target-chip {checkNetwork ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkNetwork} disabled={processing} />
								<span>🌐 {$tr('forensicsAnalyzer.optionNetwork')}</span>
							</label>
							<label class="target-chip {checkTimeline ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkTimeline} disabled={processing} />
								<span>⏱️ {$tr('forensicsAnalyzer.optionTimeline')}</span>
							</label>
							<label class="target-chip {checkAntiForensics ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkAntiForensics} disabled={processing} />
								<span>🛡️ {$tr('forensicsAnalyzer.optionAntiForensics')}</span>
							</label>
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" onclick={analyze} disabled={processing || !target.trim()}>
							{#if processing}<span class="spinner"></span> {$tr('forensicsAnalyzer.analyzing')}{:else}🔬 {$tr('forensicsAnalyzer.startAnalysis')}{/if}
						</button>
						<button class="btn-secondary" onclick={clearAll} disabled={processing}>🗑️</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('forensicsAnalyzer.resultTitle')}</h2>
					{#if error}
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					{:else if result}
						<div class="summary-bar">{result.summary}</div>

						<div class="overview-grid">
							<div class="overview-stat">
								<span class="stat-value" style="color: #ef4444">{result.critical_findings}</span>
								<span class="stat-label">{$tr('forensicsAnalyzer.criticalFindings')}</span>
							</div>
							<div class="overview-stat">
								<span class="stat-value" style="color: #f59e0b">{result.total_findings}</span>
								<span class="stat-label">{$tr('forensicsAnalyzer.totalFindings')}</span>
							</div>
							<div class="overview-stat">
								<span class="stat-value" style="color: #a855f7">{result.filesystem_info.suspicious_files.length}</span>
								<span class="stat-label">{$tr('forensicsAnalyzer.suspiciousFiles')}</span>
							</div>
							<div class="overview-stat">
								<span class="stat-value" style="color: #3b82f6">{result.memory_analysis.suspicious_processes.length}</span>
								<span class="stat-label">{$tr('forensicsAnalyzer.suspiciousProcesses')}</span>
							</div>
						</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>📊 {$tr('forensicsAnalyzer.tabOverview')}</button>
							<button class="result-tab {activeResultTab === 'files' ? 'active' : ''}" onclick={() => activeResultTab = 'files'}>📁 {$tr('forensicsAnalyzer.tabFiles')} ({result.filesystem_info.suspicious_files.length})</button>
							<button class="result-tab {activeResultTab === 'processes' ? 'active' : ''}" onclick={() => activeResultTab = 'processes'}>⚙️ {$tr('forensicsAnalyzer.tabProcesses')} ({result.memory_analysis.suspicious_processes.length})</button>
							<button class="result-tab {activeResultTab === 'network' ? 'active' : ''}" onclick={() => activeResultTab = 'network'}>🌐 {$tr('forensicsAnalyzer.tabNetwork')} ({result.memory_analysis.network_connections.length})</button>
							<button class="result-tab {activeResultTab === 'timeline' ? 'active' : ''}" onclick={() => activeResultTab = 'timeline'}>⏱️ {$tr('forensicsAnalyzer.tabTimeline')} ({result.timeline.length})</button>
							<button class="result-tab {activeResultTab === 'antiforensics' ? 'active' : ''}" onclick={() => activeResultTab = 'antiforensics'}>🛡️ {$tr('forensicsAnalyzer.tabAntiForensics')} ({result.anti_forensics_indicators.length})</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="info-grid">
								<div class="info-card">
									<h3>📁 {$tr('forensicsAnalyzer.filesystemTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.fsType')}</span><span class="info-value">{result.filesystem_info.file_system_type || 'N/A'}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.totalSize')}</span><span class="info-value">{formatSize(result.filesystem_info.total_size)}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.fileCount')}</span><span class="info-value">{result.filesystem_info.file_count}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.hiddenFiles')}</span><span class="info-value">{result.filesystem_info.hidden_files}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.encryptedFiles')}</span><span class="info-value">{result.filesystem_info.encrypted_files}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.recoverable')}</span><span class="info-value">{result.recovered_artifacts}</span></div>
								</div>
								<div class="info-card">
									<h3>⚙️ {$tr('forensicsAnalyzer.memoryTitle')}</h3>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.processCount')}</span><span class="info-value">{result.memory_analysis.process_count}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.suspiciousProcesses')}</span><span class="info-value" style="color: {result.memory_analysis.suspicious_processes.length > 0 ? '#ef4444' : '#22c55e'}">{result.memory_analysis.suspicious_processes.length}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.networkConns')}</span><span class="info-value">{result.memory_analysis.network_connections.length}</span></div>
									<div class="info-row"><span class="info-label">{$tr('forensicsAnalyzer.suspiciousConns')}</span><span class="info-value" style="color: {result.memory_analysis.network_connections.filter(c => c.suspicious).length > 0 ? '#ef4444' : '#22c55e'}">{result.memory_analysis.network_connections.filter(c => c.suspicious).length}</span></div>
								</div>
								<div class="info-card" style="grid-column: 1 / -1;">
									<h3>🛡️ {$tr('forensicsAnalyzer.antiForensicsTitle')}</h3>
									{#each result.anti_forensics_indicators.filter(a => a.detected) as a}
										<div class="info-row" style="border-left: 3px solid {getRiskColor(a.severity)}; padding-left: 8px;">
											<span class="info-label">{a.technique}</span>
											<span class="info-value" style="color: {getRiskColor(a.severity)}">{a.description}</span>
										</div>
									{/each}
									{#if result.anti_forensics_indicators.filter(a => a.detected).length === 0}
										<div class="info-row"><span class="info-value" style="color: #22c55e">✅ {$tr('forensicsAnalyzer.noAntiForensics')}</span></div>
									{/if}
								</div>
							</div>
						{:else if activeResultTab === 'files'}
							<div class="items-list">
								{#each result.filesystem_info.suspicious_files as f}
									<div class="item-card" style="border-left-color: {getRiskColor(f.risk_level)}">
										<div class="item-header">
											<span class="risk-badge" style="background: {getRiskColor(f.risk_level)}">{f.risk_level}</span>
											<span class="item-title">{f.path}</span>
											{#if f.mitre_id}<span class="mitre-badge">{f.mitre_id}</span>{/if}
										</div>
										<div class="item-meta">{$tr('forensicsAnalyzer.reason')}: {f.reason} | {$tr('forensicsAnalyzer.size')}: {formatSize(f.size)} | {$tr('forensicsAnalyzer.modified')}: {f.modified_time}</div>
									</div>
								{/each}
								{#if result.filesystem_info.suspicious_files.length === 0}<div class="empty-item">{$tr('forensicsAnalyzer.noSuspiciousFiles')}</div>{/if}
							</div>
						{:else if activeResultTab === 'processes'}
							<div class="items-list">
								{#each result.memory_analysis.suspicious_processes as p}
									<div class="item-card" style="border-left-color: {p.suspicious ? '#ef4444' : '#22c55e'}">
										<div class="item-header">
											<span class="pid-badge">PID: {p.pid}</span>
											<span class="item-title">{p.name}</span>
											{#if p.suspicious}<span class="suspicious-badge">⚠️ {$tr('forensicsAnalyzer.suspicious')}</span>{/if}
											{#if p.mitre_id}<span class="mitre-badge">{p.mitre_id}</span>{/if}
										</div>
										<div class="item-meta">{$tr('forensicsAnalyzer.user')}: {p.user} | {$tr('forensicsAnalyzer.memory')}: {p.memory_mb.toFixed(1)}MB</div>
										<div class="item-path">{p.path}</div>
										{#if p.suspicious}<div class="item-reason">{p.reason}</div>{/if}
									</div>
								{/each}
								{#if result.memory_analysis.suspicious_processes.length === 0}<div class="empty-item">{$tr('forensicsAnalyzer.noSuspiciousProcesses')}</div>{/if}
							</div>
						{:else if activeResultTab === 'network'}
							<div class="items-list">
								{#each result.memory_analysis.network_connections as c}
									<div class="item-card" style="border-left-color: {c.suspicious ? '#ef4444' : '#3b82f6'}">
										<div class="item-header">
											<span class="proto-badge">{c.protocol}</span>
											<span class="item-title">{c.local_addr} → {c.remote_addr}</span>
											{#if c.suspicious}<span class="suspicious-badge">⚠️</span>{/if}
										</div>
										<div class="item-meta">{$tr('forensicsAnalyzer.state')}: {c.state}</div>
										{#if c.suspicious && c.reason}<div class="item-reason">{c.reason}</div>{/if}
									</div>
								{/each}
								{#if result.memory_analysis.network_connections.length === 0}<div class="empty-item">{$tr('forensicsAnalyzer.noNetworkConns')}</div>{/if}
							</div>
						{:else if activeResultTab === 'timeline'}
							<div class="timeline-list">
								{#each result.timeline as t}
									<div class="timeline-item" style="border-left-color: {getRiskColor(t.significance)}">
										<div class="timeline-time">{t.timestamp}</div>
										<div class="timeline-content">
											<span class="timeline-category">{t.event_type}</span>
											<span class="timeline-event">{t.description}</span>
											<div class="timeline-details">{$tr('forensicsAnalyzer.source')}: {t.source} | MITRE: {t.mitre_id}</div>
										</div>
									</div>
								{/each}
								{#if result.timeline.length === 0}<div class="empty-item">{$tr('forensicsAnalyzer.noTimeline')}</div>{/if}
							</div>
						{:else if activeResultTab === 'antiforensics'}
							<div class="items-list">
								{#each result.anti_forensics_indicators as a}
									<div class="item-card" style="border-left-color: {a.detected ? getRiskColor(a.severity) : '#475569'}">
										<div class="item-header">
											<span class="item-title">🛡️ {a.technique}</span>
											{#if a.detected}
												<span class="risk-badge" style="background: {getRiskColor(a.severity)}">{$tr('forensicsAnalyzer.detected')}</span>
											{:else}
												<span class="risk-badge" style="background: #475569">{$tr('forensicsAnalyzer.notDetected')}</span>
											{/if}
											{#if a.mitre_id}<span class="mitre-badge">{a.mitre_id}</span>{/if}
										</div>
										<p class="item-desc">{a.description}</p>
										{#if a.detected && a.evidence}<div class="item-evidence">{$tr('forensicsAnalyzer.evidence')}: {a.evidence}</div>{/if}
									</div>
								{/each}
								{#if result.anti_forensics_indicators.length === 0}<div class="empty-item">{$tr('forensicsAnalyzer.noAntiForensics')}</div>{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔬</div>
							<p>{$tr('forensicsAnalyzer.emptyState')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="forensics_analyzer" toolName={$tr('forensicsAnalyzer.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="forensics_analyzer" /></div>
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
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0.25rem 0 0; }
	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
	.form-input { width: 100%; padding: 0.55rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { outline: none; border-color: #a855f7; box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15); }
	.form-input::placeholder { color: #475569; }
	.mode-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.35rem; }
	.mode-btn { padding: 0.4rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; cursor: pointer; font-size: 0.75rem; transition: all 0.2s; text-align: center; }
	.mode-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; box-shadow: 0 2px 6px rgba(168, 85, 247, 0.3); }
	.mode-btn:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.mode-name { font-size: 0.75rem; }
	.target-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"] { accent-color: #a855f7; width: 0.8rem; height: 0.8rem; }
	.target-chip:hover:not(.active) { border-color: rgba(148, 163, 184, 0.3); }
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
	.summary-bar { font-size: 0.8rem; color: #94a3b8; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; margin-bottom: 1rem; border: 1px solid rgba(148, 163, 184, 0.08); }
	.overview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
	.overview-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.stat-value { font-size: 1.5rem; font-weight: 700; line-height: 1; }
	.stat-label { font-size: 0.65rem; color: #94a3b8; margin-top: 0.25rem; text-align: center; }
	.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.info-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.08); border-radius: 0.5rem; }
	.info-card h3 { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.5rem; }
	.info-row { display: flex; justify-content: space-between; align-items: center; padding: 0.25rem 0; font-size: 0.8rem; }
	.info-label { color: #94a3b8; }
	.info-value { color: #f1f5f9; font-weight: 500; }
	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.result-tab { padding: 0.4rem 0.75rem; border-radius: 0.4rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.4); color: #94a3b8; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
	.result-tab.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; border-color: transparent; font-weight: 600; }
	.result-tab:hover:not(.active) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.items-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.item-card { padding: 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.5rem; border-left: 3px solid; }
	.item-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; flex-wrap: wrap; }
	.risk-badge { padding: 0.15rem 0.5rem; border-radius: 0.25rem; color: white; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
	.mitre-badge { padding: 0.15rem 0.4rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.25rem; font-size: 0.7rem; color: #818cf8; font-family: monospace; }
	.item-title { font-weight: 600; font-size: 0.85rem; word-break: break-all; color: #f1f5f9; }
	.item-meta { font-size: 0.8rem; color: #94a3b8; }
	.item-desc { font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.item-path { font-family: monospace; font-size: 0.75rem; color: #64748b; word-break: break-all; margin-top: 0.25rem; }
	.item-reason { font-size: 0.8rem; color: #ef4444; margin-top: 0.25rem; }
	.item-evidence { font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }
	.pid-badge { padding: 0.15rem 0.4rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.25rem; font-size: 0.75rem; font-family: monospace; color: #818cf8; }
	.proto-badge { padding: 0.15rem 0.4rem; background: rgba(34, 197, 94, 0.15); border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600; color: #22c55e; }
	.suspicious-badge { padding: 0.15rem 0.4rem; background: rgba(239, 68, 68, 0.15); border-radius: 0.25rem; font-size: 0.75rem; color: #ef4444; }
	.timeline-list { display: flex; flex-direction: column; gap: 0.4rem; }
	.timeline-item { display: flex; gap: 0.75rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.5rem; border-left: 3px solid; }
	.timeline-time { font-family: monospace; font-size: 0.8rem; color: #94a3b8; min-width: 140px; flex-shrink: 0; }
	.timeline-content { flex: 1; }
	.timeline-category { padding: 0.15rem 0.4rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.25rem; font-size: 0.75rem; margin-right: 0.4rem; color: #818cf8; }
	.timeline-event { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.timeline-details { font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }
	.empty-item { text-align: center; padding: 1.25rem; color: #94a3b8; font-size: 0.9rem; }
	.empty-state { text-align: center; padding: 2.5rem; color: #94a3b8; }
	.empty-icon { font-size: 3rem; margin-bottom: 0.75rem; }
</style>
