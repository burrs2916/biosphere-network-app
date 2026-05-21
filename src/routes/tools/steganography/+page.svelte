<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface SteganographyResult {
		success: boolean;
		operation: string;
		message: string;
		output_path: string | null;
		extracted_data: string | null;
	}

	let operation = 'hide';
	let hideMode = 'file';
	let coverFilePath = '';
	let secretFilePath = '';
	let secretText = '';
	let outputFilePath = '';
	let passphrase = '';
	let result: SteganographyResult | null = null;
	let error = '';
	let processing = false;
	let activeMainTab = 'analyze';
	let copied = false;

	let historyComponent: ToolHistory = $state(null!);

	async function selectFile(field: 'cover' | 'secret' | 'output') {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			let filters: Array<{ name: string; extensions: string[] }> = [];
			if (field === 'cover') {
				filters = [
					{ name: 'Image Files', extensions: ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff'] },
					{ name: 'All Files', extensions: ['*'] }
				];
			} else if (field === 'secret') {
				filters = [{ name: 'All Files', extensions: ['*'] }];
			}
			const selected = await open({ multiple: false, filters });
			if (selected) {
				const filePath = typeof selected === 'string' ? selected : (selected as any).path;
				if (field === 'cover') coverFilePath = filePath;
				else if (field === 'secret') secretFilePath = filePath;
				else outputFilePath = filePath;
			}
		} catch (e) { }
	}

	async function selectSavePath() {
		try {
			const { save } = await import('@tauri-apps/plugin-dialog');
			const selected = await save({
				filters: [
					{ name: 'Image Files', extensions: ['png', 'jpg', 'jpeg', 'bmp'] },
					{ name: 'All Files', extensions: ['*'] }
				]
			});
			if (selected) outputFilePath = selected;
		} catch (e) { }
	}

	async function process() {
		if (!coverFilePath.trim()) { error = $tr('steganography.errors.coverRequired'); return; }
		if (operation === 'hide' && hideMode === 'file' && !secretFilePath.trim()) {
			error = $tr('steganography.errors.secretRequired'); return;
		}
		if (operation === 'hide' && hideMode === 'text' && !secretText.trim()) {
			error = $tr('steganography.errors.textRequired'); return;
		}
		if (operation === 'hide' && !outputFilePath.trim()) {
			error = $tr('steganography.errors.outputRequired'); return;
		}
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<SteganographyResult>('steganography_command', {
				config: {
					operation,
					cover_file_path: coverFilePath.trim(),
					secret_file_path: operation === 'hide' && hideMode === 'file' ? secretFilePath.trim() || null : null,
					secret_text: operation === 'hide' && hideMode === 'text' ? secretText.trim() : null,
					output_file_path: operation === 'hide' ? outputFilePath.trim() || null : null,
					passphrase: passphrase.trim() || null
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					coverFilePath.trim(), JSON.stringify(result), result.message, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(coverFilePath.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		}
		finally { processing = false; }
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = true;
			setTimeout(() => { copied = false; }, 2000);
		} catch (e) { }
	}

	function clearAll() {
		coverFilePath = ''; secretFilePath = ''; outputFilePath = ''; secretText = ''; result = null; error = '';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🖼️ {$tr('steganography.title')}</h1>
			<p class="page-subtitle">{$tr('steganography.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔧</span> {$tr('steganography.mainTabs.process')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('steganography.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('steganography.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('steganography.config.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('steganography.config.operation')}</label>
						<div class="operation-toggle">
							<button class="op-btn {operation === 'hide' ? 'active' : ''}" onclick={() => operation = 'hide'} disabled={processing}>
								🔒 {$tr('steganography.config.hide')}
							</button>
							<button class="op-btn {operation === 'extract' ? 'active' : ''}" onclick={() => operation = 'extract'} disabled={processing}>
								🔓 {$tr('steganography.config.extract')}
							</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('steganography.config.coverFile')}</label>
						<div class="file-input-row">
							<input type="text" bind:value={coverFilePath} placeholder={$tr('steganography.config.coverPlaceholder')} class="form-input" disabled={processing} />
							<button class="file-btn" onclick={() => selectFile('cover')} disabled={processing}>📂</button>
						</div>
					</div>
					{#if operation === 'hide'}
						<div class="form-group">
							<label class="form-label">{$tr('steganography.config.hideMode')}</label>
							<div class="sub-tabs">
								<button class="sub-tab {hideMode === 'file' ? 'active' : ''}" onclick={() => hideMode = 'file'}>{$tr('steganography.config.fileMode')}</button>
								<button class="sub-tab {hideMode === 'text' ? 'active' : ''}" onclick={() => hideMode = 'text'}>{$tr('steganography.config.textMode')}</button>
							</div>
						</div>
						{#if hideMode === 'file'}
							<div class="form-group">
								<label class="form-label">{$tr('steganography.config.secretFile')}</label>
								<div class="file-input-row">
									<input type="text" bind:value={secretFilePath} placeholder={$tr('steganography.config.secretPlaceholder')} class="form-input" disabled={processing} />
									<button class="file-btn" onclick={() => selectFile('secret')} disabled={processing}>📂</button>
								</div>
							</div>
						{:else}
							<div class="form-group">
								<label class="form-label">{$tr('steganography.config.secretText')}</label>
								<textarea bind:value={secretText} placeholder={$tr('steganography.config.secretTextPlaceholder')} class="form-textarea" disabled={processing} rows="4"></textarea>
							</div>
						{/if}
						<div class="form-group">
							<label class="form-label">{$tr('steganography.config.outputFile')}</label>
							<div class="file-input-row">
								<input type="text" bind:value={outputFilePath} placeholder={$tr('steganography.config.outputPlaceholder')} class="form-input" disabled={processing} />
								<button class="file-btn" onclick={selectSavePath} disabled={processing}>📂</button>
							</div>
						</div>
					{/if}
					<div class="form-group">
						<label class="form-label">{$tr('steganography.config.passphrase')}</label>
						<input type="password" bind:value={passphrase} placeholder={$tr('steganography.config.passphrasePlaceholder')} class="form-input" disabled={processing} />
					</div>
					<div class="button-group">
						<button class="btn btn-primary" onclick={process} disabled={processing || !coverFilePath.trim()}>
							{#if processing}⏳ {$tr('steganography.config.processing')}{:else}🔧 {$tr('steganography.config.start')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('steganography.config.clear')}</button>
					</div>
				</div>
			</div>
			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('steganography.result.title')}</h2>
					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{:else if result}
						<div class="result-summary {result.success ? 'success' : 'failure'}">
							{#if result.success}✅{:else}❌{/if}
							{result.message}
						</div>
						{#if result.output_path}
							<div class="result-detail">
								<label class="detail-label">📁 {$tr('steganography.result.outputFile')}:</label>
								<code class="detail-value">{result.output_path}</code>
							</div>
						{/if}
						{#if result.extracted_data}
							<div class="result-detail">
								<div class="detail-header">
									<label class="detail-label">📄 {$tr('steganography.result.extractedData')}:</label>
									<button class="copy-btn" onclick={() => copyToClipboard(result!.extracted_data!)} title={$tr('steganography.result.copy')}>
										{#if copied}✅{:else}📋{/if}
									</button>
								</div>
								<textarea readonly class="form-textarea result-textarea" rows="10" value={result.extracted_data}></textarea>
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🖼️</div>
							<p>{$tr('steganography.result.emptyHint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="steganography" toolName={$tr('steganography.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="steganography" /></div>
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

	.sub-tabs { display: flex; gap: 0.2rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; }
	.sub-tab { padding: 0.35rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; white-space: nowrap; }
	.sub-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.sub-tab:hover:not(.active) { color: #e2e8f0; }

	.content-grid { display: grid; grid-template-columns: 340px 1fr; gap: 1.25rem; }
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.form-input, .form-textarea { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus, .form-textarea:focus { border-color: #a855f7; outline: none; }
	.form-textarea { resize: vertical; font-family: monospace; }

	.operation-toggle { display: flex; gap: 0.25rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; }
	.op-btn { flex: 1; padding: 0.5rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.35rem; }
	.op-btn.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; font-weight: 600; }
	.op-btn:hover:not(.active) { color: #e2e8f0; }
	.op-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.file-input-row { display: flex; gap: 0.4rem; }
	.file-input-row .form-input { flex: 1; }
	.file-btn { padding: 0.5rem 0.6rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; }
	.file-btn:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.file-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn { padding: 0.5rem 1rem; border-radius: 0.5rem; border: none; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-primary { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { background: rgba(15, 23, 42, 0.6); color: #94a3b8; border: 1px solid rgba(168, 85, 247, 0.15); }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.copy-btn { padding: 0.25rem 0.5rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.copy-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-content { color: #ef4444; font-size: 0.85rem; }

	.result-summary { padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-size: 0.9rem; }
	.result-summary.success { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); color: #22c55e; }
	.result-summary.failure { background: rgba(107, 114, 128, 0.1); border: 1px solid rgba(107, 114, 128, 0.2); color: #94a3b8; }

	.result-detail { margin-top: 0.75rem; }
	.detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem; }
	.detail-label { font-size: 0.8rem; color: #94a3b8; display: block; margin-bottom: 0.25rem; }
	.detail-value { font-family: monospace; padding: 0.35rem 0.6rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.375rem; font-size: 0.8rem; color: #f1f5f9; word-break: break-all; }
	.result-textarea { margin-top: 0.25rem; background: rgba(15, 23, 42, 0.8); }

	.empty-state { text-align: center; padding: 2.5rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { margin: 0; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
	}
</style>
