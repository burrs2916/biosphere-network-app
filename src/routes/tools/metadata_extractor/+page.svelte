<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface MetadataItem {
		key: string;
		value: string;
		category: string;
	}

	interface SensitiveFinding {
		severity: string;
		category: string;
		description: string;
		value: string;
		recommendation: string;
	}

	interface MetadataExtractResult {
		success: boolean;
		file_type: string;
		file_size: number;
		metadata: MetadataItem[];
		sensitive_findings: SensitiveFinding[];
		summary: string;
	}

	let filePath = $state('');
	let extractExif = $state(true);
	let extractPdf = $state(true);
	let extractOffice = $state(true);
	let extractImage = $state(true);
	let result: MetadataExtractResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('metadata');
	let searchQuery = $state('');
	let copied = $state(false);

	let historyComponent: ToolHistory;

	async function selectFile() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				multiple: false,
				filters: [
					{ name: 'Images', extensions: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp'] },
					{ name: 'Documents', extensions: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods'] },
					{ name: 'Archives', extensions: ['zip', 'rar', '7z', 'tar', 'gz'] },
					{ name: 'Audio', extensions: ['mp3', 'wav', 'flac', 'aac', 'ogg'] },
					{ name: 'Video', extensions: ['mp4', 'avi', 'mkv', 'mov', 'wmv'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (selected) {
				filePath = typeof selected === 'string' ? selected : (selected as any).path;
			}
		} catch (e) { }
	}

	async function extractMetadata() {
		if (!filePath.trim()) { error = $tr('metadataExtractor.errors.filePathRequired'); return; }
		processing = true; error = ''; result = null; activeResultTab = 'metadata';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<MetadataExtractResult>('extract_metadata_command', {
				config: {
					file_path: filePath.trim(),
					extract_exif: extractExif,
					extract_pdf: extractPdf,
					extract_office: extractOffice,
					extract_image: extractImage
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					filePath.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(filePath.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		}
		finally { processing = false; }
	}

	function clearAll() {
		filePath = ''; result = null; error = ''; searchQuery = '';
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = true;
			setTimeout(() => { copied = false; }, 2000);
		} catch (e) { }
	}

	async function exportResults() {
		if (!result) return;
		const data = {
			file_type: result.file_type,
			file_size: result.file_size,
			metadata: result.metadata,
			sensitive_findings: result.sensitive_findings,
			summary: result.summary
		};
		const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `metadata_${filePath.split('/').pop() || 'export'}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function getCategoryColor(category: string): string {
		const colors: Record<string, string> = {
			'basic': '#6366f1', 'Basic': '#6366f1',
			'EXIF': '#f97316', 'PDF': '#22c55e',
			'document': '#eab308', 'Document': '#eab308',
			'image': '#ec4899', 'Image': '#ec4899',
			'archive': '#14b8a6', 'Archive': '#14b8a6',
			'executable': '#ef4444', 'Executable': '#ef4444',
			'audio': '#8b5cf6', 'Audio': '#8b5cf6',
			'video': '#06b6d4', 'Video': '#06b6d4',
			'web': '#f59e0b', 'Web': '#f59e0b',
			'text': '#84cc16', 'Text': '#84cc16',
			'security': '#ef4444', 'Security': '#ef4444',
			'ID3': '#a855f7', 'system': '#6b7280', 'System': '#6b7280',
		};
		return colors[category] || '#6b7280';
	}

	function getSeverityColor(severity: string): string {
		switch (severity) {
			case 'high': return '#ef4444';
			case 'medium': return '#f59e0b';
			case 'low': return '#22c55e';
			default: return '#6b7280';
		}
	}

	function getSeverityLabel(severity: string): string {
		switch (severity) {
			case 'high': return $tr('metadataExtractor.severity.high');
			case 'medium': return $tr('metadataExtractor.severity.medium');
			case 'low': return $tr('metadataExtractor.severity.low');
			default: return severity;
		}
	}

	function formatFileSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KB`;
		if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(2)} MB`;
		return `${(bytes / 1073741824).toFixed(2)} GB`;
	}

	function getHighCount(): number { return result?.sensitive_findings.filter(f => f.severity === 'high').length ?? 0; }
	function getMediumCount(): number { return result?.sensitive_findings.filter(f => f.severity === 'medium').length ?? 0; }
	function getLowCount(): number { return result?.sensitive_findings.filter(f => f.severity === 'low').length ?? 0; }

	let filteredMetadata = $derived.by(() => {
		if (!result || result.metadata.length === 0) return [] as MetadataItem[];
		if (!searchQuery.trim()) return result.metadata;
		const q = searchQuery.toLowerCase();
		return result.metadata.filter(m =>
			m.key.toLowerCase().includes(q) ||
			m.value.toLowerCase().includes(q) ||
			m.category.toLowerCase().includes(q));
	});
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📋 {$tr('metadataExtractor.title')}</h1>
			<p class="page-subtitle">{$tr('metadataExtractor.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('metadataExtractor.mainTabs.extract')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('metadataExtractor.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('metadataExtractor.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('metadataExtractor.config.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('metadataExtractor.config.filePath')}</label>
						<div class="file-input-row">
							<input type="text" bind:value={filePath} placeholder={$tr('metadataExtractor.config.filePathPlaceholder')} class="form-input" disabled={processing} />
							<button class="file-btn" onclick={selectFile} disabled={processing}>📂</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('metadataExtractor.config.extractOptions')}</label>
						<div class="checkbox-grid">
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={extractExif} disabled={processing} />
								<span class="checkbox-text">📷 {$tr('metadataExtractor.config.extractExif')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={extractPdf} disabled={processing} />
								<span class="checkbox-text">📄 {$tr('metadataExtractor.config.extractPdf')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={extractOffice} disabled={processing} />
								<span class="checkbox-text">📝 {$tr('metadataExtractor.config.extractOffice')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={extractImage} disabled={processing} />
								<span class="checkbox-text">🖼️ {$tr('metadataExtractor.config.extractImage')}</span>
							</label>
						</div>
					</div>
					<div class="button-group">
						<button class="btn btn-primary" onclick={extractMetadata} disabled={processing || !filePath.trim()}>
							{#if processing}⏳ {$tr('metadataExtractor.config.extracting')}{:else}📋 {$tr('metadataExtractor.config.extract')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('metadataExtractor.config.clear')}</button>
					</div>
				</div>
			</div>
			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('metadataExtractor.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{:else if result}
						<div class="result-summary {result.sensitive_findings.length > 0 ? 'has-sensitive' : 'clean'}">
							{result.summary}
						</div>
						<div class="scan-stats">
							<span class="stat-badge">📁 {$tr('metadataExtractor.result.fileType')}: {result.file_type}</span>
							<span class="stat-badge">📏 {$tr('metadataExtractor.result.fileSize')}: {formatFileSize(result.file_size)}</span>
							<span class="stat-badge">📋 {$tr('metadataExtractor.result.metadataCount')}: {result.metadata.length}</span>
							{#if result.sensitive_findings.length > 0}
								<span class="stat-badge stat-danger">⚠️ {$tr('metadataExtractor.result.sensitiveCount')}: {result.sensitive_findings.length}</span>
							{/if}
						</div>

						{#if result.sensitive_findings.length > 0}
							<div class="severity-bar">
								{#if getHighCount() > 0}<span class="severity-chip high">🔴 {$tr('metadataExtractor.severity.high')} {getHighCount()}</span>{/if}
								{#if getMediumCount() > 0}<span class="severity-chip medium">🟡 {$tr('metadataExtractor.severity.medium')} {getMediumCount()}</span>{/if}
								{#if getLowCount() > 0}<span class="severity-chip low">🟢 {$tr('metadataExtractor.severity.low')} {getLowCount()}</span>{/if}
							</div>
						{/if}

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'metadata' ? 'active' : ''}" onclick={() => activeResultTab = 'metadata'}>
								📋 {$tr('metadataExtractor.result.metadata')} ({result.metadata.length})
							</button>
							<button class="result-tab {activeResultTab === 'sensitive' ? 'active' : ''}" onclick={() => activeResultTab = 'sensitive'}>
								⚠️ {$tr('metadataExtractor.result.sensitiveData')} ({result.sensitive_findings.length})
							</button>
						</div>

						{#if activeResultTab === 'metadata'}
							{#if result.metadata.length > 0}
								<div class="metadata-toolbar">
									<input type="text" bind:value={searchQuery} placeholder={$tr('metadataExtractor.result.searchPlaceholder')} class="search-input" />
									<button class="export-btn" onclick={exportResults} title={$tr('metadataExtractor.result.export')}>
										📥 {$tr('metadataExtractor.result.export')}
									</button>
									<button class="copy-btn" onclick={() => copyToClipboard(JSON.stringify(result!.metadata, null, 2))} title={$tr('metadataExtractor.result.copyAll')}>
										{#if copied}✅{:else}📋{/if}
									</button>
								</div>
								<div class="metadata-list">
									{#each filteredMetadata as item}
										<div class="metadata-item">
											<span class="metadata-cat" style="color: {getCategoryColor(item.category)}">[{item.category}]</span>
											<span class="metadata-key">{item.key}</span>
											<span class="metadata-value">{item.value}</span>
										</div>
									{/each}
									{#if filteredMetadata.length === 0 && searchQuery}
										<div class="no-match">{$tr('metadataExtractor.result.noMatch')}</div>
									{/if}
								</div>
							{:else}
								<div class="empty-sensitive">📋 {$tr('metadataExtractor.result.noMetadata')}</div>
							{/if}
						{/if}

						{#if activeResultTab === 'sensitive'}
							{#if result.sensitive_findings.length > 0}
								<div class="sensitive-list">
									{#each result.sensitive_findings as finding}
										<div class="sensitive-item severity-{finding.severity}">
											<div class="sensitive-header">
												<span class="severity-badge" style="background: {getSeverityColor(finding.severity)}">
													{getSeverityLabel(finding.severity)}
												</span>
												<span class="sensitive-category">{finding.category}</span>
											</div>
											<div class="sensitive-desc">{finding.description}</div>
											<div class="sensitive-value">🔍 {finding.value}</div>
											<div class="sensitive-recommendation">💡 {finding.recommendation}</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-sensitive">✅ {$tr('metadataExtractor.result.noSensitive')}</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📋</div>
							<p>{$tr('metadataExtractor.result.emptyHint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="metadata_extractor" toolName={$tr('metadataExtractor.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="metadata_extractor" /></div>
	{/if}
</div>

<style>
	.nd-page { padding: 1.5rem; max-width: 1200px; margin: 0 auto; min-height: 100vh; }
	.page-header { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.header-left { display: flex; flex-direction: column; }
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

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.form-input { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus { border-color: #a855f7; outline: none; }

	.file-input-row { display: flex; gap: 0.4rem; }
	.file-input-row .form-input { flex: 1; }
	.file-btn { padding: 0.5rem 0.6rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; }
	.file-btn:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.file-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
	.checkbox-label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; cursor: pointer; color: #cbd5e1; transition: color 0.2s; }
	.checkbox-label:hover { color: #e2e8f0; }
	.checkbox-text { white-space: nowrap; }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn { padding: 0.5rem 1rem; border-radius: 0.5rem; border: none; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-primary { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { background: rgba(15, 23, 42, 0.6); color: #94a3b8; border: 1px solid rgba(168, 85, 247, 0.15); }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-content { color: #ef4444; font-size: 0.85rem; }

	.result-summary { padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-size: 0.9rem; }
	.result-summary.clean { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); color: #22c55e; }
	.result-summary.has-sensitive { background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); color: #f59e0b; }

	.scan-stats { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.stat-badge { padding: 0.25rem 0.6rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.75rem; font-size: 0.75rem; color: #a5b4fc; }
	.stat-danger { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

	.severity-bar { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.severity-chip { padding: 0.25rem 0.6rem; border-radius: 0.75rem; font-size: 0.75rem; font-weight: 600; }
	.severity-chip.high { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.severity-chip.medium { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
	.severity-chip.low { background: rgba(34, 197, 94, 0.15); color: #22c55e; }

	.result-tabs { display: flex; gap: 0.2rem; margin-bottom: 0.75rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; }
	.result-tab { flex: 1; padding: 0.4rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.result-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; font-weight: 500; }
	.result-tab:hover:not(.active) { color: #e2e8f0; }

	.metadata-toolbar { display: flex; gap: 0.4rem; margin-bottom: 0.75rem; align-items: center; }
	.search-input { flex: 1; padding: 0.4rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.8rem; }
	.search-input:focus { border-color: #a855f7; outline: none; }
	.search-input::placeholder { color: #64748b; }
	.export-btn { padding: 0.4rem 0.6rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; white-space: nowrap; }
	.export-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.copy-btn { padding: 0.4rem 0.6rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.copy-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.metadata-list { display: flex; flex-direction: column; gap: 0.35rem; max-height: 500px; overflow-y: auto; }
	.metadata-item { display: grid; grid-template-columns: auto 1fr 1.5fr; gap: 0.5rem; padding: 0.4rem 0.6rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.375rem; font-size: 0.8rem; border-bottom: 1px solid rgba(168, 85, 247, 0.05); }
	.metadata-cat { font-weight: 600; font-size: 0.7rem; white-space: nowrap; }
	.metadata-key { font-weight: 500; color: #e2e8f0; }
	.metadata-value { font-family: monospace; color: #94a3b8; word-break: break-all; }
	.no-match { text-align: center; padding: 1.5rem; color: #64748b; font-size: 0.85rem; }

	.sensitive-list { display: flex; flex-direction: column; gap: 0.6rem; }
	.sensitive-item { padding: 0.75rem; border-radius: 0.5rem; border-left: 3px solid; }
	.sensitive-item.severity-high { background: rgba(239, 68, 68, 0.08); border-left-color: #ef4444; }
	.sensitive-item.severity-medium { background: rgba(245, 158, 11, 0.08); border-left-color: #f59e0b; }
	.sensitive-item.severity-low { background: rgba(34, 197, 94, 0.08); border-left-color: #22c55e; }
	.sensitive-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }
	.severity-badge { padding: 0.15rem 0.5rem; border-radius: 0.625rem; font-size: 0.7rem; font-weight: 600; color: white; }
	.sensitive-category { font-weight: 600; font-size: 0.85rem; color: #f1f5f9; }
	.sensitive-desc { font-size: 0.8rem; margin-bottom: 0.25rem; color: #94a3b8; }
	.sensitive-value { font-size: 0.8rem; font-family: monospace; margin-bottom: 0.25rem; color: #e2e8f0; }
	.sensitive-recommendation { font-size: 0.75rem; color: #64748b; font-style: italic; }

	.empty-sensitive { text-align: center; padding: 2rem; color: #94a3b8; font-size: 0.85rem; }
	.empty-state { text-align: center; padding: 2.5rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { margin: 0; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.checkbox-grid { grid-template-columns: 1fr; }
		.metadata-item { grid-template-columns: 1fr; }
	}
</style>
