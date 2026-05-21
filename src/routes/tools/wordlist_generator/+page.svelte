<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';
	import { invoke } from '@tauri-apps/api/core';

	interface WordlistResult {
		total_count: number;
		words: string[];
		config_summary: string;
	}

	let baseWords = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory = $state(null!);
	let minLength = $state(4);
	let maxLength = $state(32);
	let useLeet = $state(false);
	let useCapitalization = $state(true);
	let useAppendNumbers = $state(true);
	let useAppendSymbols = $state(false);
	let useYearSuffix = $state(true);
	let useReverse = $state(true);
	let useCombination = $state(false);
	let customNumbers = $state('');
	let customSymbols = $state('');
	let result: WordlistResult | null = $state(null as WordlistResult | null);
	let error = $state('');
	let processing = $state(false);
	let searchQuery = $state('');
	let copied = $state('');
	let activePreset = $state('');

	let filteredWords: string[] = $derived.by(() => {
		if (!result || !result.words) return [];
		return result.words.filter((w: string) => !searchQuery || w.toLowerCase().includes(searchQuery.toLowerCase()));
	});
	let displayWords = $derived(filteredWords.slice(0, 500));
	let canGenerate = $derived(baseWords.trim().length > 0);

	function applyPreset(preset: string) {
		if (activePreset === preset) {
			activePreset = '';
			return;
		}
		activePreset = preset;
		switch (preset) {
			case 'personal':
				useCapitalization = true;
				useLeet = true;
				useAppendNumbers = true;
				useAppendSymbols = false;
				useYearSuffix = true;
				useReverse = true;
				useCombination = false;
				break;
			case 'bruteforce':
				useCapitalization = true;
				useLeet = false;
				useAppendNumbers = true;
				useAppendSymbols = true;
				useYearSuffix = false;
				useReverse = false;
				useCombination = true;
				break;
			case 'targeted':
				useCapitalization = true;
				useLeet = true;
				useAppendNumbers = true;
				useAppendSymbols = true;
				useYearSuffix = true;
				useReverse = true;
				useCombination = true;
				break;
			case 'minimal':
				useCapitalization = true;
				useLeet = false;
				useAppendNumbers = false;
				useAppendSymbols = false;
				useYearSuffix = false;
				useReverse = false;
				useCombination = false;
				break;
		}
	}

	function parseConfigSummary(summary: string): string {
		if (!summary.startsWith('configSummary|')) return summary;
		const parts = summary.split('|');
		const map: Record<string, string> = {};
		for (const part of parts.slice(1)) {
			const [key, val] = part.split('=');
			if (key && val !== undefined) map[key] = val;
		}
		const enabled: string[] = [];
		if (map.caps === 'true') enabled.push($tr('wordlistGenerator.config.capitalization'));
		if (map.leet === 'true') enabled.push($tr('wordlistGenerator.config.leet'));
		if (map.numbers === 'true') enabled.push($tr('wordlistGenerator.config.appendNumbers'));
		if (map.symbols === 'true') enabled.push($tr('wordlistGenerator.config.appendSymbols'));
		if (map.years === 'true') enabled.push($tr('wordlistGenerator.config.yearSuffix'));
		if (map.reverse === 'true') enabled.push($tr('wordlistGenerator.config.reverse'));
		if (map.combo === 'true') enabled.push($tr('wordlistGenerator.config.combination'));
		return $tr('wordlistGenerator.result.configSummary', {
			baseWords: map.baseWords || '0',
			minLength: map.minLength || '4',
			maxLength: map.maxLength || '32',
			transforms: enabled.join(', ') || '-'
		});
	}

	async function generate() {
		const words = baseWords.split(/[\n,;]+/).map(w => w.trim()).filter(w => w.length > 0);
		if (words.length === 0) {
			error = $tr('wordlistGenerator.error.emptyInput');
			return;
		}

		processing = true;
		error = '';
		result = null;

		try {
			const leetMap: Record<string, string[]> = {
				'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
				's': ['5', '$'], 't': ['7'], 'l': ['1'], 'g': ['9'],
			};
			result = await invoke<WordlistResult>('generate_wordlist_command', {
				config: {
					base_words: words,
					min_length: minLength,
					max_length: maxLength,
					use_leet: useLeet,
					use_capitalization: useCapitalization,
					use_append_numbers: useAppendNumbers,
					use_append_symbols: useAppendSymbols,
					use_year_suffix: useYearSuffix,
					use_reverse: useReverse,
					use_combination: useCombination,
					custom_numbers: customNumbers.split(',').map(s => s.trim()).filter(s => s),
					custom_symbols: customSymbols.split(',').map(s => s.trim()).filter(s => s),
					leet_map: leetMap,
				}
			});
		} catch (e: any) {
			error = e.toString();
		} finally {
			processing = false;
		}
	}

	async function copyWords() {
		if (result) {
			await navigator.clipboard.writeText(result.words.join('\n'));
			copied = 'all';
			setTimeout(() => { copied = ''; }, 2000);
		}
	}

	async function copySingleWord(word: string) {
		await navigator.clipboard.writeText(word);
		copied = word;
		setTimeout(() => { copied = ''; }, 1500);
	}

	function exportResults() {
		if (!result) return;
		const data = {
			total_count: result.total_count,
			config_summary: result.config_summary,
			words: result.words,
			exported_at: new Date().toISOString()
		};
		const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `wordlist_${Date.now()}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function exportAsTxt() {
		if (!result) return;
		const blob = new Blob([result.words.join('\n')], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `wordlist_${Date.now()}.txt`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function clearAll() {
		baseWords = '';
		result = null;
		error = '';
		searchQuery = '';
		activePreset = '';
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📚 {$tr('wordlistGenerator.title')}</h1>
			<p class="page-subtitle">{$tr('wordlistGenerator.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('wordlistGenerator.mainTabs.generate')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('wordlistGenerator.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('wordlistGenerator.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('wordlistGenerator.config.title')}</h2>

					<div class="form-group">
						<label class="form-label">{$tr('wordlistGenerator.config.baseWords')}</label>
						<textarea bind:value={baseWords} placeholder={$tr('wordlistGenerator.config.baseWordsPlaceholder')} class="form-textarea" rows="4" disabled={processing}></textarea>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('wordlistGenerator.config.presets')}</label>
						<div class="preset-grid">
							<button class="preset-btn {activePreset === 'personal' ? 'active' : ''}" onclick={() => applyPreset('personal')} disabled={processing}>
								👤 {$tr('wordlistGenerator.config.presetPersonal')}
							</button>
							<button class="preset-btn {activePreset === 'bruteforce' ? 'active' : ''}" onclick={() => applyPreset('bruteforce')} disabled={processing}>
								💪 {$tr('wordlistGenerator.config.presetBruteforce')}
							</button>
							<button class="preset-btn {activePreset === 'targeted' ? 'active' : ''}" onclick={() => applyPreset('targeted')} disabled={processing}>
								🎯 {$tr('wordlistGenerator.config.presetTargeted')}
							</button>
							<button class="preset-btn {activePreset === 'minimal' ? 'active' : ''}" onclick={() => applyPreset('minimal')} disabled={processing}>
								⚡ {$tr('wordlistGenerator.config.presetMinimal')}
							</button>
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('wordlistGenerator.config.minLength')}</label>
							<input type="number" bind:value={minLength} class="form-input" min="1" max="64" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('wordlistGenerator.config.maxLength')}</label>
							<input type="number" bind:value={maxLength} class="form-input" min="1" max="128" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('wordlistGenerator.config.transformOptions')}</label>
						<div class="checkbox-grid">
							<label class="checkbox-chip {useCapitalization ? 'active' : ''}">
								<input type="checkbox" bind:checked={useCapitalization} disabled={processing} />
								<span>🔤 {$tr('wordlistGenerator.config.capitalization')}</span>
							</label>
							<label class="checkbox-chip {useLeet ? 'active' : ''}">
								<input type="checkbox" bind:checked={useLeet} disabled={processing} />
								<span>💻 {$tr('wordlistGenerator.config.leet')}</span>
							</label>
							<label class="checkbox-chip {useAppendNumbers ? 'active' : ''}">
								<input type="checkbox" bind:checked={useAppendNumbers} disabled={processing} />
								<span>🔢 {$tr('wordlistGenerator.config.appendNumbers')}</span>
							</label>
							<label class="checkbox-chip {useAppendSymbols ? 'active' : ''}">
								<input type="checkbox" bind:checked={useAppendSymbols} disabled={processing} />
								<span>🔣 {$tr('wordlistGenerator.config.appendSymbols')}</span>
							</label>
							<label class="checkbox-chip {useYearSuffix ? 'active' : ''}">
								<input type="checkbox" bind:checked={useYearSuffix} disabled={processing} />
								<span>📅 {$tr('wordlistGenerator.config.yearSuffix')}</span>
							</label>
							<label class="checkbox-chip {useReverse ? 'active' : ''}">
								<input type="checkbox" bind:checked={useReverse} disabled={processing} />
								<span>🔄 {$tr('wordlistGenerator.config.reverse')}</span>
							</label>
							<label class="checkbox-chip {useCombination ? 'active' : ''}">
								<input type="checkbox" bind:checked={useCombination} disabled={processing} />
								<span>🔗 {$tr('wordlistGenerator.config.combination')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('wordlistGenerator.config.customNumbers')}</label>
						<input type="text" bind:value={customNumbers} placeholder="123,1234,12345" class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('wordlistGenerator.config.customSymbols')}</label>
						<input type="text" bind:value={customSymbols} placeholder="!,@,#,$" class="form-input" disabled={processing} />
					</div>

					<div class="button-group">
						<button class="btn btn-primary" onclick={generate} disabled={processing || !canGenerate}>
							{#if processing}⏳ {$tr('wordlistGenerator.buttons.generating')}{:else}🔑 {$tr('wordlistGenerator.buttons.generate')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>
							🗑️ {$tr('wordlistGenerator.buttons.clear')}
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('wordlistGenerator.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{:else if result}
						<div class="result-stats">
							<div class="stat-item">
								<span class="stat-label">{$tr('wordlistGenerator.result.totalCount')}</span>
								<span class="stat-value">{result.total_count.toLocaleString()}</span>
							</div>
							<div class="stat-item">
								<span class="stat-label">{$tr('wordlistGenerator.result.displaying')}</span>
								<span class="stat-value">{displayWords.length}/{filteredWords.length.toLocaleString()}</span>
							</div>
						</div>

						<div class="config-summary">{parseConfigSummary(result.config_summary)}</div>

						<div class="result-toolbar">
							<input type="text" bind:value={searchQuery} placeholder={$tr('wordlistGenerator.result.searchPlaceholder')} class="form-input search-input" />
							<div class="toolbar-actions">
								<button class="toolbar-btn" onclick={copyWords} title={$tr('wordlistGenerator.buttons.copyAll')}>
									{#if copied === 'all'}✅{:else}📋{/if}
								</button>
								<button class="toolbar-btn" onclick={exportAsTxt} title={$tr('wordlistGenerator.result.exportTxt')}>
									📄
								</button>
								<button class="toolbar-btn" onclick={exportResults} title={$tr('wordlistGenerator.result.exportJson')}>
									📥
								</button>
							</div>
						</div>

						<div class="wordlist-container">
							{#each displayWords as word}
								<button class="word-item" onclick={() => copySingleWord(word)} title={$tr('wordlistGenerator.result.clickToCopy')}>
									{#if copied === word}✅{:else}{word}{/if}
								</button>
							{/each}
						</div>

						{#if filteredWords.length > 500}
							<p class="more-hint">{$tr('wordlistGenerator.result.moreHint', { count: (filteredWords.length - 500).toLocaleString() })}</p>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">📚</div>
							<p>{$tr('wordlistGenerator.result.empty')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="wordlist_generator" toolName={$tr('wordlistGenerator.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="wordlist_generator" />
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
	.form-input, .form-textarea {
		width: 100%;
		padding: 8px 12px;
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		color: var(--text-primary, #f1f5f9);
		font-size: 0.9rem;
		box-sizing: border-box;
	}
	.form-input:focus, .form-textarea:focus {
		outline: none;
		border-color: #a855f7;
	}
	.form-textarea {
		resize: vertical;
		font-family: monospace;
	}
	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}
	.preset-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 6px;
	}
	.preset-btn {
		padding: 6px 10px;
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		color: var(--text-secondary, #94a3b8);
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
		text-align: left;
	}
	.preset-btn.active {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.15);
		color: #c084fc;
	}
	.preset-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.4);
	}
	.checkbox-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 6px;
	}
	.checkbox-chip {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 6px 10px;
		border-radius: 8px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		cursor: pointer;
		font-size: 0.8rem;
		color: var(--text-secondary, #94a3b8);
		transition: all 0.2s;
	}
	.checkbox-chip input {
		display: none;
	}
	.checkbox-chip.active {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.15);
		color: #c084fc;
	}
	.checkbox-chip:hover:not(.active) {
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
	.btn-secondary:hover {
		opacity: 0.9;
	}
	.error-card {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 16px;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 8px;
		margin-bottom: 12px;
	}
	.error-icon {
		font-size: 1.5rem;
	}
	.error-content {
		color: #fca5a5;
	}
	.result-stats {
		display: flex;
		gap: 20px;
		margin-bottom: 12px;
	}
	.stat-item {
		display: flex;
		flex-direction: column;
	}
	.stat-label {
		font-size: 0.8rem;
		color: var(--text-secondary, #94a3b8);
	}
	.stat-value {
		font-size: 1.2rem;
		font-weight: bold;
		color: #c084fc;
	}
	.config-summary {
		font-size: 0.8rem;
		color: var(--text-secondary, #94a3b8);
		margin-bottom: 12px;
		padding: 8px;
		background: var(--bg-primary, #0f172a);
		border-radius: 6px;
	}
	.result-toolbar {
		display: flex;
		gap: 8px;
		margin-bottom: 12px;
		align-items: center;
	}
	.search-input {
		flex: 1;
	}
	.toolbar-actions {
		display: flex;
		gap: 4px;
	}
	.toolbar-btn {
		padding: 6px 10px;
		border-radius: 6px;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		background: var(--bg-primary, #0f172a);
		cursor: pointer;
		font-size: 0.9rem;
		transition: all 0.2s;
	}
	.toolbar-btn:hover {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.1);
	}
	.wordlist-container {
		max-height: 400px;
		overflow-y: auto;
		border: 1px solid var(--border, rgba(148, 163, 184, 0.2));
		border-radius: 8px;
		padding: 8px;
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		background: var(--bg-primary, #0f172a);
	}
	.word-item {
		padding: 2px 8px;
		background: var(--bg-tertiary, #334155);
		border-radius: 4px;
		font-size: 0.8rem;
		font-family: monospace;
		color: var(--text-primary, #f1f5f9);
		border: 1px solid transparent;
		cursor: pointer;
		transition: all 0.15s;
	}
	.word-item:hover {
		border-color: #a855f7;
		background: rgba(168, 85, 247, 0.15);
	}
	.more-hint {
		font-size: 0.8rem;
		color: var(--text-secondary, #94a3b8);
		text-align: center;
		margin-top: 8px;
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
		.preset-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
