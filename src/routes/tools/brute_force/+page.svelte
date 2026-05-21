<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface FoundCredential {
		username: string;
		password: string;
		service: string;
		port: number;
	}

	interface AttemptRecord {
		username: string;
		password: string;
		success: boolean;
		response_time_ms: number;
		error: string | null;
	}

	interface BruteForceResult {
		success: boolean;
		target: string;
		target_type: string;
		found_credentials: FoundCredential | null;
		attempts: number;
		time_taken_ms: number;
		attempt_log: AttemptRecord[];
		summary: string;
	}

	let target = '';
	let targetType = 'ssh';
	let username = '';
	let useWordlist = true;
	let wordlistPath = '';
	let singlePassword = '';
	let port = 22;
	let timeout = 30;
	let result: BruteForceResult | null = null;
	let error = '';
	let processing = false;
	let activeMainTab = 'analyze';
	let showAllAttempts = false;
	let copied = false;

	let historyComponent: ToolHistory;

	const servicePorts: Record<string, number> = {
		ssh: 22, ftp: 21, http: 80, smtp: 25, mysql: 3306, redis: 6379, telnet: 23, smb: 445
	};

	function onTargetTypeChange() {
		const defaultPort = servicePorts[targetType];
		if (defaultPort !== undefined) port = defaultPort;
	}

	async function selectWordlistFile() {
		try {
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({
				multiple: false,
				filters: [{ name: 'Text Files', extensions: ['txt', 'dict', 'lst'] }, { name: 'All Files', extensions: ['*'] }]
			});
			if (selected) {
				wordlistPath = typeof selected === 'string' ? selected : (selected as any).path;
			}
		} catch (e) { }
	}

	async function bruteForce() {
		if (!target.trim()) { error = $tr('bruteForce.errors.targetRequired'); return; }
		if (!username.trim()) { error = $tr('bruteForce.errors.usernameRequired'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<BruteForceResult>('brute_force_command', {
				config: {
					target: target.trim(),
					target_type: targetType,
					username: username.trim(),
					use_wordlist: useWordlist,
					wordlist_path: wordlistPath.trim() || null,
					password: singlePassword.trim() || null,
					port,
					timeout
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(
					`${target} (${username})`, JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(target.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
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
		target = ''; username = ''; singlePassword = ''; wordlistPath = ''; result = null; error = '';
	}

	$: displayAttempts = result && result.attempt_log
		? (showAllAttempts ? result.attempt_log : result.attempt_log.slice(-10))
		: [];
	$: hasMoreAttempts = result && result.attempt_log && result.attempt_log.length > 10;
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔐 {$tr('bruteForce.title')}</h1>
			<p class="page-subtitle">{$tr('bruteForce.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('bruteForce.mainTabs.attack')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('bruteForce.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('bruteForce.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('bruteForce.config.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('bruteForce.config.targetType')}</label>
						<select bind:value={targetType} onchange={onTargetTypeChange} class="form-select" disabled={processing}>
							<option value="ssh">SSH</option>
							<option value="ftp">FTP</option>
							<option value="http">HTTP Basic Auth</option>
							<option value="smtp">SMTP</option>
							<option value="mysql">MySQL</option>
							<option value="redis">Redis</option>
							<option value="telnet">Telnet</option>
							<option value="smb">SMB</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('bruteForce.config.target')}</label>
						<input type="text" bind:value={target} placeholder={$tr('bruteForce.config.targetPlaceholder')} class="form-input" disabled={processing} />
					</div>
					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('bruteForce.config.port')}</label>
							<input type="number" bind:value={port} class="form-input" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('bruteForce.config.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="300" disabled={processing} />
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('bruteForce.config.username')}</label>
						<input type="text" bind:value={username} placeholder={$tr('bruteForce.config.usernamePlaceholder')} class="form-input" disabled={processing} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('bruteForce.config.passwordMode')}</label>
						<div class="sub-tabs">
							<button class="sub-tab {useWordlist ? 'active' : ''}" onclick={() => useWordlist = true} disabled={processing}>{$tr('bruteForce.config.wordlistMode')}</button>
							<button class="sub-tab {!useWordlist ? 'active' : ''}" onclick={() => useWordlist = false} disabled={processing}>{$tr('bruteForce.config.singleMode')}</button>
						</div>
					</div>
					{#if useWordlist}
						<div class="form-group">
							<label class="form-label">{$tr('bruteForce.config.wordlistPath')}</label>
							<div class="file-input-row">
								<input type="text" bind:value={wordlistPath} placeholder={$tr('bruteForce.config.wordlistPlaceholder')} class="form-input" disabled={processing} />
								<button class="file-btn" onclick={selectWordlistFile} disabled={processing}>📂</button>
							</div>
							<span class="form-hint">{$tr('bruteForce.config.wordlistHint')}</span>
						</div>
					{:else}
						<div class="form-group">
							<label class="form-label">{$tr('bruteForce.config.singlePassword')}</label>
							<input type="password" bind:value={singlePassword} placeholder={$tr('bruteForce.config.singlePasswordPlaceholder')} class="form-input" disabled={processing} />
						</div>
					{/if}
					<div class="button-group">
						<button class="btn btn-primary" onclick={bruteForce} disabled={processing || !target.trim() || !username.trim()}>
							{#if processing}⏳ {$tr('bruteForce.config.attacking')}{:else}🔐 {$tr('bruteForce.config.start')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={processing}>🗑️ {$tr('bruteForce.config.clear')}</button>
					</div>
				</div>
			</div>
			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('bruteForce.result.title')}</h2>
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
							<span class="stat-badge">🔢 {$tr('bruteForce.result.attempts')}: {result.attempts}</span>
							<span class="stat-badge">⏱️ {$tr('bruteForce.result.time')}: {result.time_taken_ms}ms</span>
							<span class="stat-badge">🌐 {$tr('bruteForce.result.service')}: {result.target_type.toUpperCase()}</span>
						</div>
						{#if result.found_credentials}
							<div class="found-password">
								<div class="found-header">
									<span class="found-label">🔐 {$tr('bruteForce.result.foundCredentials')}</span>
									<button class="copy-btn" onclick={() => copyToClipboard(`${result!.found_credentials!.username}:${result!.found_credentials!.password}`)} title={$tr('bruteForce.result.copy')}>
										{#if copied}✅{:else}📋{/if}
									</button>
								</div>
								<div class="found-creds">
									<span>{$tr('bruteForce.result.username')}: <code>{result.found_credentials.username}</code></span>
									<span>{$tr('bruteForce.result.password')}: <code>{result.found_credentials.password}</code></span>
									<span>{$tr('bruteForce.result.service')}: <code>{result.found_credentials.service.toUpperCase()} :{result.found_credentials.port}</code></span>
								</div>
							</div>
						{/if}
						{#if result.attempt_log && result.attempt_log.length > 0}
							<div class="attempt-log">
								<h3 class="log-title">{$tr('bruteForce.result.attemptLog')}</h3>
								<div class="log-entries">
									{#each displayAttempts as attempt}
										<div class="log-entry {attempt.success ? 'success' : ''}">
											<span class="log-status">{attempt.success ? '✅' : '❌'}</span>
											<span class="log-password">{attempt.password}</span>
											<span class="log-time">{attempt.response_time_ms}ms</span>
											{#if attempt.error}
												<span class="log-error">{attempt.error}</span>
											{/if}
										</div>
									{/each}
								</div>
								{#if hasMoreAttempts && !showAllAttempts}
									<button class="show-more-btn" onclick={() => showAllAttempts = true}>
										{$tr('bruteForce.result.showAll')} ({result.attempt_log.length})
									</button>
								{:else if hasMoreAttempts && showAllAttempts}
									<button class="show-more-btn" onclick={() => showAllAttempts = false}>
										{$tr('bruteForce.result.collapse')}
									</button>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔐</div>
							<p>{$tr('bruteForce.result.emptyHint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="brute_force" toolName={$tr('bruteForce.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="brute_force" /></div>
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
	.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.25rem; }
	.form-input, .form-select { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); color: #f1f5f9; font-size: 0.85rem; box-sizing: border-box; transition: border-color 0.2s; }
	.form-input:focus, .form-select:focus { border-color: #a855f7; outline: none; }
	.form-hint { font-size: 0.7rem; color: #64748b; margin-top: 0.2rem; display: block; }

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

	.scan-stats { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.stat-badge { padding: 0.25rem 0.6rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.75rem; font-size: 0.75rem; color: #a5b4fc; }

	.found-password { padding: 1rem; background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 0.75rem; margin-bottom: 0.75rem; }
	.found-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.found-label { font-weight: 600; color: #22c55e; font-size: 0.9rem; }
	.found-creds { display: flex; flex-direction: column; gap: 0.35rem; }
	.found-creds span { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #e2e8f0; }
	.found-creds code { font-family: monospace; padding: 0.2rem 0.5rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.375rem; font-size: 0.8rem; color: #f1f5f9; }

	.attempt-log { margin-top: 0.75rem; }
	.log-title { font-size: 0.85rem; font-weight: 600; color: #f1f5f9; margin: 0 0 0.5rem; }
	.log-entries { max-height: 300px; overflow-y: auto; }
	.log-entry { display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0.5rem; border-radius: 0.375rem; font-size: 0.75rem; color: #94a3b8; }
	.log-entry.success { background: rgba(34, 197, 94, 0.1); color: #22c55e; }
	.log-entry:not(:last-child) { border-bottom: 1px solid rgba(168, 85, 247, 0.05); }
	.log-status { font-size: 0.7rem; }
	.log-password { font-family: monospace; flex: 1; }
	.log-time { color: #64748b; font-size: 0.7rem; }
	.log-error { color: #ef4444; font-size: 0.7rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

	.show-more-btn { width: 100%; padding: 0.4rem; border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.375rem; background: transparent; color: #a855f7; cursor: pointer; font-size: 0.75rem; margin-top: 0.5rem; transition: all 0.2s; }
	.show-more-btn:hover { background: rgba(168, 85, 247, 0.1); }

	.empty-state { text-align: center; padding: 2.5rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { margin: 0; font-size: 0.85rem; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.form-row { grid-template-columns: 1fr; }
	}
</style>
