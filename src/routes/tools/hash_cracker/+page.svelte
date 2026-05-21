<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface HashAttempt {
		password: string;
		hash: string;
		match_found: boolean;
	}

	interface HashCrackResult {
		success: boolean;
		found_password: string | null;
		hash_type_detected: string;
		passwords_tried: number;
		time_taken_ms: number;
		summary: string;
		attempts: HashAttempt[];
	}

	let hash = '';
	let hashType = 'auto';
	let useBuiltinWordlist = true;
	let customWordlistPath = '';
	let maxPasswords = 10000;
	let timeout = 300;
	let result: HashCrackResult | null = null;
	let error = '';
	let processing = false;
	let activeMainTab = 'analyze';
	let showAllAttempts = false;
	let batchHashes = '';
	let batchResults: Array<{ hash: string; result: HashCrackResult | null; error: string }> = [];
	let batchProcessing = false;
	let activeSubTab = 'single';
	let hashToCompute = '';
	let computeHashType = 'md5';
	let computedHash = '';
	let computing = false;
	let detectedType = '';
	let copied = false;

	let historyComponent: ToolHistory;

	$: {
		if (hash.trim()) {
			const h = hash.trim();
			if (/^[0-9a-fA-F]{32}$/.test(h)) detectedType = 'MD5';
			else if (/^[0-9a-fA-F]{40}$/.test(h)) detectedType = 'SHA1';
			else if (/^[0-9a-fA-F]{64}$/.test(h)) detectedType = 'SHA256';
			else if (/^[0-9a-fA-F]{96}$/.test(h)) detectedType = 'SHA384';
			else if (/^[0-9a-fA-F]{128}$/.test(h)) detectedType = 'SHA512';
			else detectedType = '';
		} else {
			detectedType = '';
		}
	}

	async function crack() {
		if (!hash.trim()) { error = $tr('hashCracker.errors.hashRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<HashCrackResult>('crack_hash_command', {
				config: {
					hash: hash.trim(),
					hash_type: hashType,
					use_builtin_wordlist: useBuiltinWordlist,
					wordlist_path: customWordlistPath || null,
					max_passwords: maxPasswords,
					timeout: timeout
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(hash.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) { await historyComponent.saveHistory(hash.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed'); }
		}
		finally { processing = false; }
	}

	async function batchCrack() {
		const lines = batchHashes.split('\n').map(l => l.trim()).filter(l => l.length > 0);
		if (lines.length === 0) return;
		batchProcessing = true;
		batchResults = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			for (const h of lines) {
				try {
					const r = await invoke<HashCrackResult>('crack_hash_command', {
						config: {
							hash: h,
							hash_type: 'auto',
							use_builtin_wordlist: useBuiltinWordlist,
							wordlist_path: customWordlistPath || null,
							max_passwords: maxPasswords,
							timeout: timeout
						}
					});
					batchResults = [...batchResults, { hash: h, result: r, error: '' }];
				} catch (e: any) {
					batchResults = [...batchResults, { hash: h, result: null, error: e.toString() }];
				}
			}
		} finally {
			batchProcessing = false;
		}
	}

	async function computeHash() {
		if (!hashToCompute.trim()) return;
		computing = true;
		computedHash = '';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			computedHash = await invoke<string>('compute_hash_command', {
				hashType: computeHashType,
				input: hashToCompute
			});
		} catch (e: any) {
			computedHash = '';
		} finally {
			computing = false;
		}
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = true;
			setTimeout(() => { copied = false; }, 2000);
		} catch (e) { }
	}

	function clearAll() { hash = ''; result = null; error = ''; detectedType = ''; }

	function getHashTypeColor(type: string): string {
		switch (type.toLowerCase()) {
			case 'md5': return '#f97316';
			case 'sha1': return '#eab308';
			case 'sha256': return '#22c55e';
			case 'sha384': return '#6366f1';
			case 'sha512': return '#a855f7';
			default: return '#6b7280';
		}
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔓 {$tr('hashCracker.title')}</h1>
			<p class="page-subtitle">{$tr('hashCracker.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔓</span> {$tr('hashCracker.mainTabs.crack')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('hashCracker.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('hashCracker.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="sub-tabs">
			<button class="sub-tab {activeSubTab === 'single' ? 'active' : ''}" onclick={() => activeSubTab = 'single'}>{$tr('hashCracker.subTabs.single')}</button>
			<button class="sub-tab {activeSubTab === 'batch' ? 'active' : ''}" onclick={() => activeSubTab = 'batch'}>{$tr('hashCracker.subTabs.batch')}</button>
			<button class="sub-tab {activeSubTab === 'compute' ? 'active' : ''}" onclick={() => activeSubTab = 'compute'}>{$tr('hashCracker.subTabs.compute')}</button>
		</div>

		{#if activeSubTab === 'single'}
			<div class="content-grid">
				<div class="input-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.config.title')}</h2>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.hashValue')}</label>
							<textarea bind:value={hash} placeholder={$tr('hashCracker.config.hashPlaceholder')} class="form-textarea" disabled={processing} rows="3" />
							{#if detectedType}
								<div class="detected-type-hint">
									<span class="detect-icon">🔍</span>
									{$tr('hashCracker.config.detectedType')} <span class="detect-badge" style="background: rgba({getHashTypeColor(detectedType.toLowerCase())}, 0.15); color: {getHashTypeColor(detectedType.toLowerCase())}">{detectedType}</span>
								</div>
							{/if}
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.hashType')}</label>
							<select bind:value={hashType} class="form-select" disabled={processing}>
								<option value="auto">{$tr('hashCracker.config.autoDetect')}</option>
								<option value="md5">MD5</option>
								<option value="sha1">SHA1</option>
								<option value="sha256">SHA256</option>
								<option value="sha384">SHA384</option>
								<option value="sha512">SHA512</option>
							</select>
						</div>
						<div class="checkbox-group">
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={useBuiltinWordlist} disabled={processing} />
								{$tr('hashCracker.config.useBuiltinWordlist')}
							</label>
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.customWordlist')}</label>
							<input type="text" bind:value={customWordlistPath} placeholder="/path/to/wordlist.txt" class="form-input" disabled={processing} />
						</div>
						<div class="form-row">
							<div class="form-group">
								<label class="form-label">{$tr('hashCracker.config.maxPasswords')}</label>
								<input type="number" bind:value={maxPasswords} class="form-input" min="100" max="1000000" disabled={processing} />
							</div>
							<div class="form-group">
								<label class="form-label">{$tr('hashCracker.config.timeout')}</label>
								<input type="number" bind:value={timeout} class="form-input" min="10" max="3600" disabled={processing} />
							</div>
						</div>
						<div class="button-group">
							<button class="btn btn-primary" onclick={crack} disabled={processing || !hash.trim()}>
								{#if processing}⏳ {$tr('hashCracker.config.cracking')}{:else}🔓 {$tr('hashCracker.config.startCrack')}{/if}
							</button>
							<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('hashCracker.config.clear')}</button>
						</div>
					</div>
				</div>
				<div class="result-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.result.title')}</h2>
						{#if error}
							<div class="error-card">
								<div class="error-icon">⚠️</div>
								<div class="error-content"><p>{error}</p></div>
							</div>
						{:else if result}
							<div class="result-summary {result.success ? 'success' : 'failure'}">
								{#if result.success}✅{:else}❌{/if}
								{result.summary}
							</div>
							<div class="scan-stats">
								<span class="stat-badge">🔢 {$tr('hashCracker.result.attempts')}: {result.passwords_tried}</span>
								<span class="stat-badge">⏱️ {$tr('hashCracker.result.timeTaken')}: {result.time_taken_ms}ms</span>
								<span class="stat-badge" style="background: rgba({getHashTypeColor(result.hash_type_detected)}, 0.15); color: {getHashTypeColor(result.hash_type_detected)}">
									📌 {$tr('hashCracker.result.type')}: {result.hash_type_detected}
								</span>
							</div>
							{#if result.found_password}
								<div class="found-password">
									<span class="found-label">🔓 {$tr('hashCracker.result.foundPassword')}:</span>
									<code class="found-value">{result.found_password}</code>
									<button class="copy-btn" onclick={() => copyToClipboard(result!.found_password!)} title={$tr('hashCracker.result.copy')}>
										{#if copied}✅{:else}📋{/if}
									</button>
								</div>
							{/if}
							{#if result.attempts.length > 0}
								<div class="attempts-section">
									<div class="attempts-header">
										<span>{$tr('hashCracker.result.recentAttempts')}</span>
										<button class="btn-small" onclick={() => showAllAttempts = !showAllAttempts}>
											{showAllAttempts ? $tr('hashCracker.result.collapse') : $tr('hashCracker.result.showAll')}
										</button>
									</div>
									<div class="attempts-list">
										{#each (showAllAttempts ? result.attempts : result.attempts.slice(0, 10)) as attempt}
											<div class="attempt-item {attempt.match_found ? 'match' : ''}">
												<span class="attempt-pwd">{attempt.password}</span>
												<span class="attempt-hash">{attempt.hash.slice(0, 16)}...</span>
												<span class="attempt-status">
													{#if attempt.match_found}✅ {$tr('hashCracker.result.match')}{:else}❌ {$tr('hashCracker.result.noMatch')}{/if}
												</span>
											</div>
										{/each}
									</div>
									{#if !showAllAttempts && result.attempts.length > 10}
										<div class="more-attempts">{$tr('hashCracker.result.moreAttempts', { count: result.attempts.length - 10 })}</div>
									{/if}
								</div>
							{/if}
						{:else}
							<div class="empty-state">
								<div class="empty-icon">🔓</div>
								<p>{$tr('hashCracker.result.emptyHint')}</p>
							</div>
						{/if}
					</div>
				</div>
			</div>
		{:else if activeSubTab === 'batch'}
			<div class="content-grid">
				<div class="input-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.batch.title')}</h2>
						<p class="section-desc">{$tr('hashCracker.batch.desc')}</p>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.batch.hashList')}</label>
							<textarea bind:value={batchHashes} placeholder={$tr('hashCracker.batch.placeholder')} class="form-textarea batch-textarea" disabled={batchProcessing} rows="8" />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.maxPasswords')}</label>
							<input type="number" bind:value={maxPasswords} class="form-input" min="100" max="1000000" disabled={batchProcessing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="10" max="3600" disabled={batchProcessing} />
						</div>
						<div class="button-group">
							<button class="btn btn-primary" onclick={batchCrack} disabled={batchProcessing || !batchHashes.trim()}>
								{#if batchProcessing}⏳ {$tr('hashCracker.batch.processing')}{:else}🔓 {$tr('hashCracker.batch.start')}{/if}
							</button>
							<button class="btn btn-secondary" onclick={() => { batchHashes = ''; batchResults = []; }} disabled={batchProcessing}>🗑️ {$tr('hashCracker.config.clear')}</button>
						</div>
					</div>
				</div>
				<div class="result-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.batch.resultTitle')}</h2>
						{#if batchResults.length > 0}
							<div class="batch-stats">
								<span class="stat-badge success-badge">✅ {$tr('hashCracker.batch.cracked')}: {batchResults.filter(r => r.result?.success).length}</span>
								<span class="stat-badge fail-badge">❌ {$tr('hashCracker.batch.notCracked')}: {batchResults.filter(r => r.result && !r.result.success).length}</span>
								<span class="stat-badge">📊 {$tr('hashCracker.batch.total')}: {batchResults.length}</span>
							</div>
							<div class="batch-results-list">
								{#each batchResults as br, i}
									<div class="batch-result-item {br.result?.success ? 'success' : 'failure'}">
										<div class="batch-hash-label">
											<span class="batch-index">#{i + 1}</span>
											<code class="batch-hash-value">{br.hash.slice(0, 32)}{br.hash.length > 32 ? '...' : ''}</code>
										</div>
										{#if br.result?.success}
											<div class="batch-found">
												🔓 <code>{br.result.found_password}</code>
											</div>
										{:else if br.result}
											<div class="batch-not-found">❌ {$tr('hashCracker.batch.notFound')}</div>
										{:else}
											<div class="batch-error">⚠️ {br.error}</div>
										{/if}
									</div>
								{/each}
							</div>
						{:else}
							<div class="empty-state">
								<div class="empty-icon">📋</div>
								<p>{$tr('hashCracker.batch.emptyHint')}</p>
							</div>
						{/if}
					</div>
				</div>
			</div>
		{:else if activeSubTab === 'compute'}
			<div class="content-grid">
				<div class="input-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.compute.title')}</h2>
						<p class="section-desc">{$tr('hashCracker.compute.desc')}</p>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.compute.input')}</label>
							<input type="text" bind:value={hashToCompute} placeholder={$tr('hashCracker.compute.inputPlaceholder')} class="form-input" disabled={computing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('hashCracker.config.hashType')}</label>
							<select bind:value={computeHashType} class="form-select" disabled={computing}>
								<option value="md5">MD5</option>
								<option value="sha1">SHA1</option>
								<option value="sha256">SHA256</option>
								<option value="sha384">SHA384</option>
								<option value="sha512">SHA512</option>
							</select>
						</div>
						<div class="button-group">
							<button class="btn btn-primary" onclick={computeHash} disabled={computing || !hashToCompute.trim()}>
								{#if computing}⏳ {$tr('hashCracker.compute.computing')}{:else}🔐 {$tr('hashCracker.compute.start')}{/if}
							</button>
							<button class="btn btn-secondary" onclick={() => { hashToCompute = ''; computedHash = ''; }}>🗑️ {$tr('hashCracker.config.clear')}</button>
						</div>
					</div>
				</div>
				<div class="result-section">
					<div class="section-card">
						<h2 class="section-title">{$tr('hashCracker.compute.resultTitle')}</h2>
						{#if computedHash}
							<div class="compute-result">
								<div class="compute-result-header">
									<span class="compute-type-badge" style="background: rgba({getHashTypeColor(computeHashType)}, 0.15); color: {getHashTypeColor(computeHashType)}">
										{computeHashType.toUpperCase()}
									</span>
									<button class="copy-btn" onclick={() => copyToClipboard(computedHash)} title={$tr('hashCracker.result.copy')}>
										{#if copied}✅{:else}📋{/if}
									</button>
								</div>
								<code class="compute-hash-value">{computedHash}</code>
								<div class="compute-input-info">
									<span class="info-label">{$tr('hashCracker.compute.originalInput')}:</span>
									<span class="info-value">{hashToCompute}</span>
								</div>
							</div>
						{:else}
							<div class="empty-state">
								<div class="empty-icon">🔐</div>
								<p>{$tr('hashCracker.compute.emptyHint')}</p>
							</div>
						{/if}
					</div>
				</div>
			</div>
		{/if}
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="hash_cracker" toolName={$tr('hashCracker.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="hash_cracker" /></div>
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

	.sub-tabs { display: flex; gap: 0.2rem; margin-bottom: 1rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; }
	.sub-tab { padding: 0.35rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; white-space: nowrap; }
	.sub-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.sub-tab:hover:not(.active) { color: #e2e8f0; }

	.content-grid { display: grid; grid-template-columns: 340px 1fr; gap: 1.25rem; }
	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: -0.5rem 0 0.75rem; }

	.form-group { margin-bottom: 0.75rem; }
	.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.form-input, .form-select, .form-textarea { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus, .form-select:focus, .form-textarea:focus { border-color: #a855f7; outline: none; }
	.form-textarea { resize: vertical; font-family: monospace; }
	.batch-textarea { min-height: 200px; }

	.detected-type-hint { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.35rem; font-size: 0.75rem; color: #94a3b8; }
	.detect-icon { font-size: 0.8rem; }
	.detect-badge { padding: 0.15rem 0.5rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600; }

	.checkbox-group { margin-bottom: 0.75rem; }
	.checkbox-label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; cursor: pointer; color: #94a3b8; }

	.button-group { display: flex; gap: 0.5rem; margin-top: 1rem; }
	.btn { padding: 0.5rem 1rem; border-radius: 0.5rem; border: none; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
	.btn-primary { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-secondary { background: rgba(15, 23, 42, 0.6); color: #94a3b8; border: 1px solid rgba(168, 85, 247, 0.15); }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.btn-small { padding: 0.25rem 0.75rem; border-radius: 0.375rem; border: none; cursor: pointer; font-size: 0.75rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; border: 1px solid rgba(168, 85, 247, 0.15); }
	.btn-small:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.copy-btn { padding: 0.25rem 0.5rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.copy-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-content { color: #ef4444; font-size: 0.85rem; }

	.result-summary { padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-size: 0.9rem; }
	.result-summary.success { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); color: #22c55e; }
	.result-summary.failure { background: rgba(107, 114, 128, 0.1); border: 1px solid rgba(107, 114, 128, 0.2); color: #94a3b8; }

	.scan-stats { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.stat-badge { padding: 0.25rem 0.6rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.75rem; font-size: 0.75rem; color: #c4b5fd; }
	.success-badge { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
	.fail-badge { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

	.found-password { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 0.5rem; margin-bottom: 1rem; }
	.found-label { font-weight: 600; color: #22c55e; font-size: 0.9rem; }
	.found-value { padding: 0.35rem 0.75rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.375rem; font-family: monospace; font-size: 0.85rem; color: #f1f5f9; }

	.attempts-section { border-top: 1px solid rgba(168, 85, 247, 0.15); padding-top: 0.75rem; }
	.attempts-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; font-size: 0.8rem; color: #94a3b8; }
	.attempts-list { display: flex; flex-direction: column; gap: 0.25rem; }
	.attempt-item { display: grid; grid-template-columns: 1fr 1fr auto; gap: 0.5rem; padding: 0.4rem 0.5rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.375rem; font-size: 0.75rem; }
	.attempt-item.match { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); }
	.attempt-pwd { font-family: monospace; color: #f1f5f9; }
	.attempt-hash { font-family: monospace; color: #94a3b8; }
	.attempt-status { font-weight: 500; }
	.more-attempts { text-align: center; font-size: 0.75rem; color: #94a3b8; padding: 0.5rem; }

	.batch-stats { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
	.batch-results-list { display: flex; flex-direction: column; gap: 0.5rem; max-height: 500px; overflow-y: auto; }
	.batch-result-item { padding: 0.75rem; border-radius: 0.5rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.1); }
	.batch-result-item.success { border-color: rgba(34, 197, 94, 0.2); }
	.batch-result-item.failure { border-color: rgba(107, 114, 128, 0.2); }
	.batch-hash-label { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem; }
	.batch-index { font-size: 0.75rem; color: #94a3b8; font-weight: 600; }
	.batch-hash-value { font-family: monospace; font-size: 0.75rem; color: #94a3b8; }
	.batch-found { color: #22c55e; font-size: 0.85rem; }
	.batch-found code { background: rgba(15, 23, 42, 0.6); padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.8rem; }
	.batch-not-found { color: #94a3b8; font-size: 0.8rem; }
	.batch-error { color: #ef4444; font-size: 0.8rem; }

	.compute-result { padding: 1rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.5rem; }
	.compute-result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
	.compute-type-badge { padding: 0.25rem 0.6rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600; }
	.compute-hash-value { display: block; font-family: monospace; font-size: 0.85rem; color: #f1f5f9; word-break: break-all; padding: 0.75rem; background: rgba(15, 23, 42, 0.8); border-radius: 0.375rem; margin-bottom: 0.75rem; }
	.compute-input-info { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; }
	.info-label { color: #94a3b8; }
	.info-value { color: #f1f5f9; }

	.empty-state { text-align: center; padding: 2.5rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { margin: 0; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
	}
</style>
