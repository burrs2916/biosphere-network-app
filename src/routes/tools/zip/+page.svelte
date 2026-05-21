<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { open } from '@tauri-apps/plugin-dialog';
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface ZipFileInfo {
		name: string;
		size: number;
		compressed_size: number;
		is_dir: boolean;
		is_encrypted: boolean;
	}

	interface ZipExtractResult {
		success: boolean;
		files_extracted: number;
		total_size: number;
		output_path: string;
		error: string | null;
	}

	interface ZipBruteForceResult {
		success: boolean;
		password: string | null;
		attempts: number;
		elapsed_ms: number;
		error: string | null;
	}

	let zipPath = $state('');
	let activeMainTab = $state('analyze');
	let activeModeTab = $state('extract');
	let historyComponent: ToolHistory;
	let outputDir = $state('');
	let password = $state('');
	let files: ZipFileInfo[] = $state([]);
	let isEncrypted = $state(false);
	let extracting = $state(false);
	let error = $state('');
	let result: ZipExtractResult | null = $state(null as ZipExtractResult | null);
	let copied = $state('');

	let bruteForceMode = $state('dictionary');
	let dictionaryPath = $state('');
	let bruteForceRunning = $state(false);
	let bruteForceResult: ZipBruteForceResult | null = $state(null as ZipBruteForceResult | null);
	let bruteForceProgress = $state(0);
	let bruteForceTotal = $state(0);

	let encryptedCount = $derived(files.filter(f => f.is_encrypted).length);
	let totalOriginalSize = $derived(files.reduce((sum, f) => sum + f.size, 0));
	let totalCompressedSize = $derived(files.reduce((sum, f) => sum + f.compressed_size, 0));
	let compressionRatio = $derived(
		totalOriginalSize > 0 ? ((1 - totalCompressedSize / totalOriginalSize) * 100).toFixed(1) : '0'
	);

	async function selectZipFile() {
		const selected = await open({
			multiple: false,
			filters: [{ name: 'ZIP', extensions: ['zip'] }]
		});
		if (selected) {
			zipPath = selected as string;
			await loadZipInfo();
		}
	}

	async function selectOutputDir() {
		const selected = await open({ directory: true });
		if (selected) {
			outputDir = selected as string;
		}
	}

	async function selectDictionaryFile() {
		const selected = await open({
			multiple: false,
			filters: [{ name: 'Text', extensions: ['txt', 'dict', 'lst'] }]
		});
		if (selected) {
			dictionaryPath = selected as string;
		}
	}

	async function loadZipInfo() {
		if (!zipPath) return;
		error = '';
		files = [];
		result = null;
		bruteForceResult = null;
		try {
			isEncrypted = await invoke('check_zip_encryption_command', { zipPath });
			files = await invoke('list_zip_files_command', { zipPath });
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	async function extractZip() {
		if (!zipPath || !outputDir) {
			error = $tr('zip.error.selectPaths');
			return;
		}
		if (isEncrypted && !password) {
			error = $tr('zip.error.passwordRequired');
			return;
		}
		extracting = true;
		error = '';
		result = null;
		try {
			result = await invoke<ZipExtractResult>('extract_zip_command', {
				zipPath,
				outputDir,
				password: password || null
			});
			if (!result.success) {
				error = result.error || $tr('zip.error.extraction');
			}
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			extracting = false;
		}
	}

	async function bruteForceZip() {
		if (!zipPath) {
			error = $tr('zip.error.selectZip');
			return;
		}
		bruteForceRunning = true;
		bruteForceResult = null;
		error = '';
		bruteForceProgress = 0;
		try {
			bruteForceResult = await invoke<ZipBruteForceResult>('brute_force_zip_command', {
				zipPath,
				mode: bruteForceMode,
				dictionaryPath: dictionaryPath || null
			});
			if (bruteForceResult.success && bruteForceResult.password) {
				password = bruteForceResult.password;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			bruteForceRunning = false;
		}
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return bytes + ' B';
		if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
		if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
		return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
	}

	async function copyToClipboard(text: string, id: string) {
		await navigator.clipboard.writeText(text);
		copied = id;
		setTimeout(() => { copied = ''; }, 1500);
	}

	function clearAll() {
		zipPath = '';
		outputDir = '';
		password = '';
		files = [];
		isEncrypted = false;
		error = '';
		result = null;
		bruteForceResult = null;
		dictionaryPath = '';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📦 {$tr('zip.title')}</h1>
			<p class="page-subtitle">{$tr('zip.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">📦</span> {$tr('zip.mainTabs.extract')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('zip.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('zip.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('zip.config.title')}</h2>

					<div class="form-group">
						<label class="form-label">📁 {$tr('zip.labels.selectZip')}</label>
						<div class="input-group">
							<input type="text" bind:value={zipPath} placeholder={$tr('zip.placeholders.zipPath')} class="form-input" readonly />
							<button class="btn btn-secondary" onclick={selectZipFile}>
								📂 {$tr('zip.buttons.browse')}
							</button>
						</div>
					</div>

					{#if files.length > 0}
						<div class="stats-grid">
							<div class="stat-item">
								<span class="stat-label">{$tr('zip.stats.totalFiles')}</span>
								<span class="stat-value">{files.length}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('zip.stats.encryptedFiles')}</span>
								<span class="stat-value {encryptedCount > 0 ? 'warning' : ''}">{encryptedCount}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('zip.stats.originalSize')}</span>
								<span class="stat-value">{formatSize(totalOriginalSize)}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('zip.stats.compressedSize')}</span>
								<span class="stat-value">{formatSize(totalCompressedSize)}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('zip.stats.ratio')}</span>
								<span class="stat-value">{compressionRatio}%</span>
							</div>
						</div>
					{/if}

					{#if isEncrypted}
						<div class="warning-card">
							<div class="warning-icon">🔐</div>
							<div class="warning-text">
								<strong>{$tr('zip.info.encrypted')}</strong>
								<p>{$tr('zip.info.encryptedDesc')}</p>
							</div>
						</div>

						<div class="mode-tabs">
							<button class="mode-tab {activeModeTab === 'extract' ? 'active' : ''}" onclick={() => activeModeTab = 'extract'}>
								🔑 {$tr('zip.modeTabs.manual')}
							</button>
							<button class="mode-tab {activeModeTab === 'bruteforce' ? 'active' : ''}" onclick={() => activeModeTab = 'bruteforce'}>
								💪 {$tr('zip.modeTabs.bruteforce')}
							</button>
						</div>

						{#if activeModeTab === 'extract'}
							<div class="form-group">
								<label class="form-label">🔑 {$tr('zip.labels.password')}</label>
								<div class="input-group">
									<input type="password" bind:value={password} placeholder={$tr('zip.placeholders.password')} class="form-input" />
									<button class="btn btn-icon" onclick={() => copyToClipboard(password, 'pwd')} title={$tr('zip.buttons.copy')}>
										{#if copied === 'pwd'}✅{:else}📋{/if}
									</button>
								</div>
							</div>
						{:else}
							<div class="form-group">
								<label class="form-label">{$tr('zip.bruteforce.mode')}</label>
								<div class="mode-grid">
									<button class="mode-btn {bruteForceMode === 'dictionary' ? 'active' : ''}" onclick={() => bruteForceMode = 'dictionary'}>
										📚 {$tr('zip.bruteforce.dictionary')}
									</button>
									<button class="mode-btn {bruteForceMode === 'common' ? 'active' : ''}" onclick={() => bruteForceMode = 'common'}>
										🔑 {$tr('zip.bruteforce.common')}
									</button>
									<button class="mode-btn {bruteForceMode === 'numeric' ? 'active' : ''}" onclick={() => bruteForceMode = 'numeric'}>
										🔢 {$tr('zip.bruteforce.numeric')}
									</button>
								</div>
							</div>

							{#if bruteForceMode === 'dictionary'}
								<div class="form-group">
									<label class="form-label">{$tr('zip.bruteforce.dictPath')}</label>
									<div class="input-group">
										<input type="text" bind:value={dictionaryPath} placeholder={$tr('zip.bruteforce.dictPlaceholder')} class="form-input" readonly />
										<button class="btn btn-secondary" onclick={selectDictionaryFile}>
											📂 {$tr('zip.buttons.browse')}
										</button>
									</div>
								</div>
							{/if}

							<button class="btn btn-primary" onclick={bruteForceZip} disabled={!zipPath || bruteForceRunning}>
								{#if bruteForceRunning}⏳ {$tr('zip.bruteforce.running')}{:else}💪 {$tr('zip.bruteforce.start')}{/if}
							</button>

							{#if bruteForceResult}
								{#if bruteForceResult.success && bruteForceResult.password}
									<div class="success-card">
										<div class="success-icon">✅</div>
										<div class="success-text">
											<strong>{$tr('zip.bruteforce.found')}</strong>
											<p class="found-password">🔑 {bruteForceResult.password}</p>
											<p>{$tr('zip.bruteforce.attempts', { count: bruteForceResult.attempts.toString() })} | {$tr('zip.bruteforce.elapsed', { time: bruteForceResult.elapsed_ms.toString() })}</p>
										</div>
									</div>
								{:else if !bruteForceResult.success}
									<div class="error-card">
										<div class="error-icon">❌</div>
										<div class="error-text">
											<strong>{$tr('zip.bruteforce.failed')}</strong>
											<p>{bruteForceResult.error || $tr('zip.bruteforce.noPassword')}</p>
										</div>
									</div>
								{/if}
							{/if}
						{/if}
					{/if}

					<div class="form-group">
						<label class="form-label">📂 {$tr('zip.labels.outputDir')}</label>
						<div class="input-group">
							<input type="text" bind:value={outputDir} placeholder={$tr('zip.placeholders.outputDir')} class="form-input" readonly />
							<button class="btn btn-secondary" onclick={selectOutputDir}>
								📂 {$tr('zip.buttons.browse')}
							</button>
						</div>
					</div>

					<div class="button-group">
						<button class="btn btn-primary" onclick={extractZip} disabled={!zipPath || !outputDir || extracting || (isEncrypted && !password)}>
							{#if extracting}⏳ {$tr('zip.buttons.extracting')}{:else}🔓 {$tr('zip.buttons.extract')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={extracting}>
							🗑️ {$tr('zip.buttons.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">📋 {$tr('zip.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">❌</div>
							<div class="error-text">{error}</div>
						</div>
					{/if}

					{#if result && result.success}
						<div class="success-card">
							<div class="success-icon">✅</div>
							<div class="success-text">
								<strong>{$tr('zip.result.success')}</strong>
								<p>{$tr('zip.result.extracted', { count: result.files_extracted.toString() })}</p>
								<p>{$tr('zip.result.totalSize', { size: formatSize(result.total_size) })}</p>
							</div>
						</div>
					{/if}

					{#if files.length > 0}
						<div class="files-list">
							<h3>📄 {$tr('zip.files.title')} ({files.length})</h3>
							<div class="files-table">
								<div class="files-header">
									<div class="file-name-col">{$tr('zip.files.name')}</div>
									<div class="file-size-col">{$tr('zip.files.size')}</div>
									<div class="file-compressed-col">{$tr('zip.files.compressed')}</div>
									<div class="file-encrypted-col">{$tr('zip.files.encrypted')}</div>
								</div>
								<div class="files-body">
									{#each files as file}
										<div class="file-row {file.is_dir ? 'directory' : ''}">
											<div class="file-name-col">
												{#if file.is_dir}📁{:else if file.is_encrypted}🔐{:else}📄{/if}
												{file.name}
											</div>
											<div class="file-size-col">{formatSize(file.size)}</div>
											<div class="file-compressed-col">{formatSize(file.compressed_size)}</div>
											<div class="file-encrypted-col">
												{#if file.is_encrypted}
													<span class="badge badge-danger">{$tr('zip.files.yes')}</span>
												{:else}
													<span class="badge badge-success">{$tr('zip.files.no')}</span>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							</div>
						</div>
					{:else if zipPath && !error}
						<div class="empty-state">
							<div class="empty-icon">📦</div>
							<p>{$tr('zip.result.empty')}</p>
						</div>
					{:else if !zipPath}
						<div class="empty-state">
							<div class="empty-icon">📦</div>
							<p>{$tr('zip.result.noFile')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="zip" toolName={$tr('zip.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="zip" />
		</div>
	{/if}
</div>

<style>
	.nd-page {
		padding: 20px;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}
	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 20px;
	}
	.back-link {
		color: var(--text-secondary, #94a3b8);
		text-decoration: none;
		font-size: 0.85rem;
	}
	.page-title {
		font-size: 1.5rem;
		margin: 8px 0 4px;
		color: var(--text-primary, #f1f5f9);
	}
	.page-subtitle {
		color: var(--text-secondary, #94a3b8);
		font-size: 0.9rem;
	}
	.tabs {
		display: flex;
		gap: 4px;
		margin-bottom: 16px;
		background: var(--bg-secondary, #1e293b);
		border-radius: 10px;
		padding: 4px;
	}
	.tab-btn {
		flex: 1;
		padding: 8px 16px;
		border: none;
		border-radius: 8px;
		background: transparent;
		cursor: pointer;
		font-size: 0.9rem;
		color: var(--text-secondary, #94a3b8);
		transition: all 0.2s;
	}
	.tab-btn.active {
		background: linear-gradient(135deg, #a855f7, #6366f1);
		color: white;
	}
	.tab-btn:hover:not(.active) {
		background: var(--bg-primary, #0f172a);
	}
	.tab-icon {
		margin-right: 4px;
	}
	.content-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 20px;
	}
	.section-card {
		background: var(--bg-secondary, #1e293b);
		border-radius: 12px;
		padding: 20px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.1));
	}
	.section-title {
		font-size: 1.1rem;
		margin-bottom: 16px;
		color: var(--text-primary, #f1f5f9);
	}
	.form-group {
		margin-bottom: 12px;
	}
	.form-label {
		display: block;
		font-size: 0.85rem;
		color: var(--text-secondary, #94a3b8);
		margin-bottom: 4px;
	}
	.form-input {
		width: 100%;
		padding: 8px 12px;
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		color: var(--text-primary, #f1f5f9);
		font-size: 0.9rem;
		box-sizing: border-box;
	}
	.form-input:focus {
		outline: none;
		border-color: #a855f7;
	}
	.input-group {
		display: flex;
		gap: 6px;
	}
	.input-group .form-input {
		flex: 1;
	}
	.stats-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 8px;
		margin-bottom: 12px;
		padding: 10px;
		background: var(--bg-primary, #0f172a);
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.1));
	}
	.stat-item {
		display: flex;
		flex-direction: column;
		text-align: center;
	}
	.stat-label {
		font-size: 0.7rem;
		color: var(--text-secondary, #94a3b8);
	}
	.stat-value {
		font-size: 1rem;
		font-weight: bold;
		color: #c084fc;
	}
	.stat-value.warning {
		color: #f59e0b;
	}
	.warning-card {
		background: rgba(245, 158, 11, 0.1);
		border: 1px solid rgba(245, 158, 11, 0.3);
		border-radius: 8px;
		padding: 12px;
		margin-bottom: 12px;
		display: flex;
		align-items: flex-start;
		gap: 10px;
	}
	.warning-icon {
		font-size: 1.3rem;
		flex-shrink: 0;
	}
	.warning-text {
		flex: 1;
	}
	.warning-text strong {
		color: #fbbf24;
		font-size: 0.9rem;
		display: block;
		margin-bottom: 2px;
	}
	.warning-text p {
		color: #d97706;
		font-size: 0.8rem;
		margin: 0;
	}
	.mode-tabs {
		display: flex;
		gap: 4px;
		margin-bottom: 12px;
		background: var(--bg-primary, #0f172a);
		border-radius: 8px;
		padding: 3px;
	}
	.mode-tab {
		flex: 1;
		padding: 6px 12px;
		border: none;
		border-radius: 6px;
		background: transparent;
		cursor: pointer;
		font-size: 0.8rem;
		color: var(--text-secondary, #94a3b8);
		transition: all 0.2s;
	}
	.mode-tab.active {
		background: rgba(168, 85, 247, 0.2);
		color: #c084fc;
	}
	.mode-tab:hover:not(.active) {
		background: rgba(148, 163, 184, 0.1);
	}
	.mode-grid {
		display: grid;
		grid-template-columns: 1fr 1fr 1fr;
		gap: 6px;
	}
	.mode-btn {
		padding: 6px 10px;
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		color: var(--text-secondary, #94a3b8);
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
		text-align: center;
	}
	.mode-btn.active {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.15);
		color: #c084fc;
	}
	.mode-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.4);
	}
	.button-group {
		display: flex;
		gap: 8px;
		margin-top: 12px;
	}
	.btn {
		padding: 8px 16px;
		border-radius: 8px;
		border: none;
		cursor: pointer;
		font-size: 0.9rem;
		transition: all 0.2s;
	}
	.btn-primary {
		background: linear-gradient(135deg, #a855f7, #6366f1);
		color: white;
		flex: 1;
	}
	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary:hover:not(:disabled) {
		opacity: 0.9;
	}
	.btn-secondary {
		background: var(--bg-tertiary, #334155);
		color: var(--text-primary, #f1f5f9);
	}
	.btn-icon {
		padding: 8px 10px;
		border-radius: 6px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		cursor: pointer;
		font-size: 0.9rem;
	}
	.btn-icon:hover {
		border-color: #a855f7;
	}
	.error-card {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 8px;
		margin-bottom: 12px;
	}
	.error-icon {
		font-size: 1.3rem;
		flex-shrink: 0;
	}
	.error-text {
		color: #fca5a5;
		font-size: 0.9rem;
	}
	.error-text strong {
		display: block;
		margin-bottom: 2px;
	}
	.success-card {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px;
		background: rgba(34, 197, 94, 0.1);
		border: 1px solid rgba(34, 197, 94, 0.3);
		border-radius: 8px;
		margin-bottom: 12px;
	}
	.success-icon {
		font-size: 1.3rem;
		flex-shrink: 0;
	}
	.success-text {
		color: #86efac;
	}
	.success-text strong {
		display: block;
		margin-bottom: 2px;
	}
	.success-text p {
		font-size: 0.85rem;
		margin: 2px 0;
	}
	.found-password {
		font-family: monospace;
		font-size: 1.1rem;
		padding: 4px 8px;
		background: rgba(168, 85, 247, 0.2);
		border-radius: 4px;
		display: inline-block;
		margin: 4px 0;
	}
	.files-list {
		margin-top: 12px;
	}
	.files-list h3 {
		color: var(--text-primary, #f1f5f9);
		font-size: 1rem;
		margin-bottom: 8px;
	}
	.files-table {
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		border-radius: 8px;
		overflow: hidden;
	}
	.files-header {
		display: grid;
		grid-template-columns: 2fr 1fr 1fr 1fr;
		gap: 8px;
		padding: 8px 12px;
		background: var(--bg-primary, #0f172a);
		font-weight: 600;
		color: var(--text-secondary, #94a3b8);
		font-size: 0.8rem;
	}
	.files-body {
		max-height: 350px;
		overflow-y: auto;
	}
	.file-row {
		display: grid;
		grid-template-columns: 2fr 1fr 1fr 1fr;
		gap: 8px;
		padding: 6px 12px;
		border-top: 1px solid var(--border, rgba(148, 163, 184, 0.1));
		font-size: 0.8rem;
		color: var(--text-primary, #f1f5f9);
	}
	.file-row.directory {
		background: rgba(148, 163, 184, 0.05);
	}
	.file-name-col {
		display: flex;
		align-items: center;
		gap: 4px;
		word-break: break-all;
	}
	.file-size-col, .file-compressed-col, .file-encrypted-col {
		display: flex;
		align-items: center;
	}
	.badge {
		padding: 2px 6px;
		border-radius: 4px;
		font-size: 0.7rem;
		font-weight: 600;
	}
	.badge-danger {
		background: rgba(239, 68, 68, 0.15);
		color: #fca5a5;
	}
	.badge-success {
		background: rgba(34, 197, 94, 0.15);
		color: #86efac;
	}
	.empty-state {
		text-align: center;
		padding: 40px;
		color: var(--text-secondary, #94a3b8);
	}
	.empty-icon {
		font-size: 3rem;
		margin-bottom: 12px;
	}

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}
		.stats-grid {
			grid-template-columns: repeat(2, 1fr);
		}
		.mode-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
