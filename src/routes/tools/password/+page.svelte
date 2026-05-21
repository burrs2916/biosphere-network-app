<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';
	import { invoke } from '@tauri-apps/api/core';

	let passwordLength = $state(16);
	let activeMainTab = $state('analyze');
	let activeResultTab = $state('passwords');
	let historyComponent: ToolHistory;
	let includeLowercase = $state(true);
	let includeUppercase = $state(true);
	let includeNumbers = $state(true);
	let includeSymbols = $state(true);
	let excludeAmbiguous = $state(false);
	let excludeSimilar = $state(false);
	let count = $state(1);

	let passwords: string[] = $state([]);
	let passphrase = $state('');
	let passphraseWordCount = $state(5);
	let passphraseSeparator = $state('-');

	let testPassword = $state('');
	let strengthScore = $state(0);
	let strengthLevel = $state('');
	let strengthFeedback: string[] = $state([]);

	let generating = $state(false);
	let error = $state('');
	let copied = $state('');

	let canGenerate = $derived(includeLowercase || includeUppercase || includeNumbers || includeSymbols);

	function getStrengthLabel(level: string): string {
		switch (level) {
			case 'Weak': return $tr('passwordGenerator.strength.weak');
			case 'Medium': return $tr('passwordGenerator.strength.medium');
			case 'Strong': return $tr('passwordGenerator.strength.strong');
			case 'VeryStrong': return $tr('passwordGenerator.strength.veryStrong');
			default: return level;
		}
	}

	function getStrengthColor(level: string): string {
		switch (level) {
			case 'Weak': return '#ef4444';
			case 'Medium': return '#f59e0b';
			case 'Strong': return '#22c55e';
			case 'VeryStrong': return '#06b6d4';
			default: return '#94a3b8';
		}
	}

	function translateFeedback(key: string): string {
		if (key.startsWith('feedback.')) {
			const fbKey = key.replace('feedback.', '');
			return $tr(`passwordGenerator.feedback.${fbKey}`);
		}
		return key;
	}

	async function generatePasswords() {
		if (!canGenerate) {
			error = $tr('passwordGenerator.error.selectCharType');
			return;
		}

		generating = true;
		error = '';
		passwords = [];

		try {
			const config = {
				length: passwordLength,
				include_lowercase: includeLowercase,
				include_uppercase: includeUppercase,
				include_numbers: includeNumbers,
				include_symbols: includeSymbols,
				exclude_ambiguous: excludeAmbiguous,
				exclude_similar: excludeSimilar,
				count: count
			};

			const result = await invoke<any>('generate_passwords_command', { config });

			if (result.success) {
				passwords = result.passwords;
				activeResultTab = 'passwords';
			} else {
				error = result.error || $tr('passwordGenerator.error.generation');
			}
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			generating = false;
		}
	}

	async function generatePassphrase() {
		generating = true;
		error = '';
		passphrase = '';

		try {
			passphrase = await invoke<string>('generate_passphrase_command', {
				wordCount: passphraseWordCount,
				separator: passphraseSeparator
			});
			activeResultTab = 'passphrase';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			generating = false;
		}
	}

	async function checkStrength() {
		if (!testPassword.trim()) {
			error = $tr('passwordGenerator.error.emptyTest');
			return;
		}

		try {
			const result = await invoke<any>('check_password_strength_command', {
				password: testPassword
			});

			strengthScore = result.score;
			strengthLevel = result.level;
			strengthFeedback = result.feedback;
			activeResultTab = 'strength';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = text;
			setTimeout(() => { copied = ''; }, 2000);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	function exportResults() {
		if (passwords.length === 0 && !passphrase) return;
		const data: Record<string, any> = {};
		if (passwords.length > 0) {
			data.passwords = passwords;
			data.config = { length: passwordLength, includeLowercase, includeUppercase, includeNumbers, includeSymbols, excludeAmbiguous, excludeSimilar, count };
		}
		if (passphrase) {
			data.passphrase = passphrase;
			data.passphraseConfig = { wordCount: passphraseWordCount, separator: passphraseSeparator };
		}
		if (strengthScore > 0) {
			data.strengthCheck = { password: testPassword, score: strengthScore, level: strengthLevel, feedback: strengthFeedback };
		}
		const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'password-results.json';
		a.click();
		URL.revokeObjectURL(url);
	}

	function clearAll() {
		passwords = [];
		passphrase = '';
		testPassword = '';
		error = '';
		strengthScore = 0;
		strengthLevel = '';
		strengthFeedback = [];
	}
</script>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔑 {$tr('passwordGenerator.title')}</h1>
			<p class="page-subtitle">{$tr('passwordGenerator.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔑</span> {$tr('passwordGenerator.mainTabs.generate')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('passwordGenerator.mainTabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('passwordGenerator.mainTabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('passwordGenerator.config.title')}</h2>

					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.config.length')}: <strong>{passwordLength}</strong></label>
						<input type="range" min="8" max="128" bind:value={passwordLength} class="range-slider" disabled={generating} />
						<div class="range-labels">
							<span>8</span>
							<span>64</span>
							<span>128</span>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.config.charTypes')}</label>
						<div class="checkbox-grid">
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={includeLowercase} disabled={generating} />
								<span class="checkbox-text">a-z {$tr('passwordGenerator.config.lowercase')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={includeUppercase} disabled={generating} />
								<span class="checkbox-text">A-Z {$tr('passwordGenerator.config.uppercase')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={includeNumbers} disabled={generating} />
								<span class="checkbox-text">0-9 {$tr('passwordGenerator.config.numbers')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={includeSymbols} disabled={generating} />
								<span class="checkbox-text">!@# {$tr('passwordGenerator.config.symbols')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.config.advancedOptions')}</label>
						<div class="checkbox-grid">
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={excludeSimilar} disabled={generating} />
								<span class="checkbox-text">{$tr('passwordGenerator.config.excludeSimilar')}</span>
							</label>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={excludeAmbiguous} disabled={generating} />
								<span class="checkbox-text">{$tr('passwordGenerator.config.excludeAmbiguous')}</span>
							</label>
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.config.count')}: <strong>{count}</strong></label>
						<input type="range" min="1" max="50" bind:value={count} class="range-slider" disabled={generating} />
					</div>

					<div class="button-group">
						<button class="btn btn-primary" onclick={generatePasswords} disabled={!canGenerate || generating}>
							{#if generating}⏳ {$tr('passwordGenerator.config.generating')}{:else}🔑 {$tr('passwordGenerator.config.generate')}{/if}
						</button>
						<button class="btn btn-secondary" onclick={clearAll} disabled={generating}>🗑️ {$tr('passwordGenerator.config.clear')}</button>
					</div>
				</div>

				<div class="section-card" style="margin-top: 1.25rem;">
					<h2 class="section-title">🔐 {$tr('passwordGenerator.passphrase.title')}</h2>
					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.passphrase.wordCount')}: <strong>{passphraseWordCount}</strong></label>
						<input type="range" min="3" max="12" bind:value={passphraseWordCount} class="range-slider" disabled={generating} />
					</div>
					<div class="form-group">
						<label class="form-label">{$tr('passwordGenerator.passphrase.separator')}</label>
						<select bind:value={passphraseSeparator} class="form-input" disabled={generating}>
							<option value="-">- (hyphen)</option>
							<option value=" ">(space)</option>
							<option value="_">_ (underscore)</option>
							<option value=".">. (dot)</option>
							<option value="">(none)</option>
						</select>
					</div>
					<button class="btn btn-secondary" onclick={generatePassphrase} disabled={generating} style="width:100%">
						🎲 {$tr('passwordGenerator.passphrase.generate')}
					</button>
				</div>

				<div class="section-card" style="margin-top: 1.25rem;">
					<h2 class="section-title">💪 {$tr('passwordGenerator.strength.title')}</h2>
					<div class="form-group">
						<input type="text" bind:value={testPassword} placeholder={$tr('passwordGenerator.strength.placeholder')} class="form-input" disabled={generating} />
					</div>
					<button class="btn btn-info" onclick={checkStrength} disabled={!testPassword.trim() || generating} style="width:100%">
						🔍 {$tr('passwordGenerator.strength.check')}
					</button>
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('passwordGenerator.result.title')}</h2>

					{#if error}
						<div class="error-card">
							<div class="error-icon">⚠️</div>
							<div class="error-content"><p>{error}</p></div>
						</div>
					{/if}

					{#if passwords.length > 0 || passphrase || strengthScore > 0}
						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'passwords' ? 'active' : ''}" onclick={() => activeResultTab = 'passwords'}>
								🔑 {$tr('passwordGenerator.result.passwords')} ({passwords.length})
							</button>
							<button class="result-tab {activeResultTab === 'passphrase' ? 'active' : ''}" onclick={() => activeResultTab = 'passphrase'}>
								🔐 {$tr('passwordGenerator.result.passphrase')}
							</button>
							<button class="result-tab {activeResultTab === 'strength' ? 'active' : ''}" onclick={() => activeResultTab = 'strength'}>
								💪 {$tr('passwordGenerator.result.strength')}
							</button>
						</div>

						<div class="result-toolbar">
							<button class="export-btn" onclick={exportResults} title={$tr('passwordGenerator.result.export')}>
								📥 {$tr('passwordGenerator.result.export')}
							</button>
						</div>

						{#if activeResultTab === 'passwords'}
							{#if passwords.length > 0}
								<div class="scan-stats">
									<span class="stat-badge">✅ {$tr('passwordGenerator.result.generatedCount')}: {passwords.length}</span>
									<span class="stat-badge">📏 {$tr('passwordGenerator.result.length')}: {passwordLength}</span>
								</div>
								<div class="password-list">
									{#each passwords as pwd, index}
										<div class="password-item">
											<span class="password-index">{index + 1}.</span>
											<code class="password-text">{pwd}</code>
											<button class="copy-btn" onclick={() => copyToClipboard(pwd)} title={$tr('passwordGenerator.result.copy')}>
												{#if copied === pwd}✅{:else}📋{/if}
											</button>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔑</div>
									<p>{$tr('passwordGenerator.result.noPasswords')}</p>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'passphrase'}
							{#if passphrase}
								<div class="passphrase-result">
									<code class="passphrase-text">{passphrase}</code>
									<button class="copy-btn" onclick={() => copyToClipboard(passphrase)} title={$tr('passwordGenerator.result.copy')}>
										{#if copied === passphrase}✅{:else}📋{/if}
									</button>
								</div>
								<div class="scan-stats" style="margin-top: 0.75rem;">
									<span class="stat-badge">📝 {$tr('passwordGenerator.passphrase.wordCount')}: {passphraseWordCount}</span>
									<span class="stat-badge">📏 {$tr('passwordGenerator.result.length')}: {passphrase.length}</span>
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔐</div>
									<p>{$tr('passwordGenerator.result.noPassphrase')}</p>
								</div>
							{/if}
						{/if}

						{#if activeResultTab === 'strength'}
							{#if strengthScore > 0}
								<div class="strength-result">
									<div class="strength-meter">
										<div class="strength-bar" style="width: {(strengthScore / 10 * 100)}%; background: {getStrengthColor(strengthLevel)};"></div>
									</div>
									<div class="strength-info">
										<span class="strength-score">{strengthScore}/10</span>
										<span class="strength-level" style="background: {getStrengthColor(strengthLevel)}22; color: {getStrengthColor(strengthLevel)}">
											{getStrengthLabel(strengthLevel)}
										</span>
									</div>
									{#if strengthFeedback.length > 0}
										<ul class="feedback-list">
											{#each strengthFeedback as fb}
												<li>💡 {translateFeedback(fb)}</li>
											{/each}
										</ul>
									{/if}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">💪</div>
									<p>{$tr('passwordGenerator.result.noStrength')}</p>
								</div>
							{/if}
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🔑</div>
							<p>{$tr('passwordGenerator.result.emptyHint')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card"><ToolHistory toolType="password" toolName={$tr('passwordGenerator.title')} bind:this={historyComponent} /></div>
	{:else if activeMainTab === 'help'}
		<div class="section-card"><ToolHelp toolType="password" /></div>
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

	.range-slider { width: 100%; height: 6px; border-radius: 3px; outline: none; -webkit-appearance: none; background: rgba(168, 85, 247, 0.15); cursor: pointer; }
	.range-slider::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; border-radius: 50%; background: linear-gradient(135deg, #a855f7, #6366f1); cursor: pointer; box-shadow: 0 2px 6px rgba(168, 85, 247, 0.4); }
	.range-slider:disabled { opacity: 0.5; cursor: not-allowed; }
	.range-labels { display: flex; justify-content: space-between; font-size: 0.75rem; color: #64748b; margin-top: 0.25rem; }

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
	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }
	.btn-info { background: rgba(6, 182, 212, 0.15); color: #06b6d4; border: 1px solid rgba(6, 182, 212, 0.2); }
	.btn-info:hover:not(:disabled) { background: rgba(6, 182, 212, 0.25); }
	.btn-info:disabled { opacity: 0.5; cursor: not-allowed; }

	.error-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; margin-bottom: 0.75rem; }
	.error-icon { font-size: 1.25rem; }
	.error-content { color: #ef4444; font-size: 0.85rem; }

	.result-tabs { display: flex; gap: 0.25rem; margin-bottom: 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.5rem; padding: 0.2rem; }
	.result-tab { flex: 1; padding: 0.4rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.result-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; font-weight: 600; }
	.result-tab:hover:not(.active) { color: #cbd5e1; }

	.result-toolbar { display: flex; justify-content: flex-end; gap: 0.5rem; margin-bottom: 0.75rem; }
	.export-btn { padding: 0.3rem 0.6rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.export-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.scan-stats { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
	.stat-badge { padding: 0.25rem 0.6rem; background: rgba(99, 102, 241, 0.15); border-radius: 0.75rem; font-size: 0.75rem; color: #a5b4fc; }

	.password-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.password-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.6rem 0.75rem; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 0.5rem; transition: border-color 0.2s; }
	.password-item:hover { border-color: rgba(168, 85, 247, 0.3); }
	.password-index { font-size: 0.75rem; color: #64748b; min-width: 1.5rem; }
	.password-text { font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace; font-size: 0.85rem; word-break: break-all; color: #e2e8f0; flex: 1; background: none; }
	.copy-btn { padding: 0.3rem 0.5rem; border-radius: 0.375rem; border: 1px solid rgba(168, 85, 247, 0.15); background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.copy-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }

	.passphrase-result { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem; background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.15); border-radius: 0.5rem; }
	.passphrase-text { font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace; font-size: 1rem; font-weight: 600; color: #fbbf24; flex: 1; background: none; }

	.strength-result { margin-top: 0.5rem; }
	.strength-meter { height: 10px; background: rgba(15, 23, 42, 0.4); border-radius: 5px; overflow: hidden; margin-bottom: 0.75rem; }
	.strength-bar { height: 100%; transition: width 0.3s ease, background-color 0.3s ease; border-radius: 5px; }
	.strength-info { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
	.strength-score { font-weight: 700; font-size: 1rem; color: #f1f5f9; }
	.strength-level { font-weight: 600; padding: 0.25rem 0.75rem; border-radius: 0.75rem; font-size: 0.85rem; }
	.feedback-list { list-style: none; padding: 0; margin: 0; }
	.feedback-list li { padding: 0.4rem 0; color: #94a3b8; font-size: 0.85rem; border-bottom: 1px solid rgba(168, 85, 247, 0.08); }
	.feedback-list li:last-child { border-bottom: none; }

	.empty-state { text-align: center; padding: 3rem 1rem; color: #64748b; }
	.empty-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
	.empty-state p { font-size: 0.9rem; margin: 0; }

	@media (max-width: 1024px) {
		.content-grid { grid-template-columns: 1fr; }
	}
</style>
