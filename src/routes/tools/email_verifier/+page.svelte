<script lang="ts">
	import { tr, t } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface EmailVerifyEntry {
		email: string;
		local_part: string;
		domain: string;
		is_valid_format: boolean;
		mx_records_found: boolean;
		mx_records: string[];
		smtp_reachable: boolean | null;
		is_disposable: boolean;
		is_role_account: boolean;
		is_catch_all: boolean | null;
		spf_record: string | null;
		dkim_record: string | null;
		dmarc_record: string | null;
		breach_count: number | null;
		risk_score: number;
		risk_level: string;
		status: string;
		details: string;
	}

	interface EmailVerifyResult {
		results: EmailVerifyEntry[];
		total_checked: number;
		valid_count: number;
		invalid_count: number;
		risky_count: number;
		summary: string;
	}

	let emails = $state('');
	let activeMainTab = $state('check');
	let historyComponent: ToolHistory;
	let checkSmtp = $state(true);
	let checkSpf = $state(true);
	let checkDkim = $state(false);
	let checkDmarc = $state(true);
	let checkBreach = $state(false);
	let result: EmailVerifyResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let selectedEntry: EmailVerifyEntry | null = $state(null);

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && emails.trim()) {
			verify();
		}
	}

	async function verify() {
		const emailList = emails.split(/[\n,;]+/).map(e => e.trim()).filter(e => e.length > 0);
		if (emailList.length === 0) { error = t('emailVerifier.error.emptyInput'); return; }
		processing = true; error = ''; result = null; selectedEntry = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<EmailVerifyResult>('verify_email_command', {
				config: {
					emails: emailList,
					timeout: 10,
					check_smtp: checkSmtp,
					check_format: true,
					check_spf: checkSpf,
					check_dkim: checkDkim,
					check_dmarc: checkDmarc,
					check_breach: checkBreach,
				}
			});
		} catch (e: any) { error = e.toString(); }
		finally { processing = false; }
	}

	function clearAll() {
		emails = '';
		result = null;
		error = '';
		selectedEntry = null;
		activeResultTab = 'overview';
	}

	function getRiskColor(level: string): string {
		switch (level) {
			case 'critical': return '#ef4444';
			case 'high': return '#f87171';
			case 'medium': return '#facc15';
			case 'low': return '#a3e635';
			case 'safe': return '#10b981';
			default: return '#94a3b8';
		}
	}

	function getRiskBg(level: string): string {
		switch (level) {
			case 'critical': return 'rgba(239,68,68,0.15)';
			case 'high': return 'rgba(248,113,113,0.15)';
			case 'medium': return 'rgba(250,204,21,0.15)';
			case 'low': return 'rgba(163,230,53,0.15)';
			case 'safe': return 'rgba(16,185,129,0.15)';
			default: return 'rgba(148,163,184,0.1)';
		}
	}

	function getStatusIcon(status: string): string {
		switch (status) {
			case 'Valid': return '✅';
			case 'Disposable': return '⚠️';
			case 'Invalid Domain': return '🔴';
			case 'Invalid Format': return '❌';
			case 'Unreachable': return '🚫';
			case 'Catch-All': return '📬';
			case 'Role Account': return '👤';
			case 'Breached': return '🔓';
			default: return '⚠️';
		}
	}

	function getValidCount(): number {
		if (!result) return 0;
		return result.results.filter((e: EmailVerifyEntry) => e.status === 'Valid').length;
	}

	function getDisposableCount(): number {
		if (!result) return 0;
		return result.results.filter((e: EmailVerifyEntry) => e.is_disposable).length;
	}

	function getRoleCount(): number {
		if (!result) return 0;
		return result.results.filter((e: EmailVerifyEntry) => e.is_role_account).length;
	}

	function getHighRiskCount(): number {
		if (!result) return 0;
		return result.results.filter((e: EmailVerifyEntry) => e.risk_level === 'high' || e.risk_level === 'critical').length;
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">📧 {$tr('emailVerifier.title')}</h1>
			<p class="page-subtitle">{$tr('emailVerifier.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'check' ? 'active' : ''}" onclick={() => activeMainTab = 'check'}>
			<span class="tab-icon">🔍</span> {$tr('emailVerifier.tabs.check')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('emailVerifier.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('emailVerifier.tabs.help')}
		</button>
	</div>

	{#if activeMainTab === 'check'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('emailVerifier.config.title')}</h2>
					<p class="section-desc">{$tr('emailVerifier.config.desc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('emailVerifier.config.emails')}</label>
						<textarea bind:value={emails} placeholder={$tr('emailVerifier.config.emailsPlaceholder')} class="form-textarea" rows="6" disabled={processing}></textarea>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('emailVerifier.config.checkOptions')}</label>
						<div class="chip-group">
							<label class="target-chip {checkSmtp ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkSmtp} disabled={processing} />
								<span>🔌 {$tr('emailVerifier.config.checkSmtp')}</span>
							</label>
							<label class="target-chip {checkSpf ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkSpf} disabled={processing} />
								<span>🛡️ SPF</span>
							</label>
							<label class="target-chip {checkDkim ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDkim} disabled={processing} />
								<span>🔑 DKIM</span>
							</label>
							<label class="target-chip {checkDmarc ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkDmarc} disabled={processing} />
								<span>📧 DMARC</span>
							</label>
							<label class="target-chip {checkBreach ? 'active' : ''}">
								<input type="checkbox" bind:checked={checkBreach} disabled={processing} />
								<span>🔓 {$tr('emailVerifier.config.checkBreach')}</span>
							</label>
						</div>
					</div>

					<div class="btn-group">
						<button class="action-btn" onclick={verify} disabled={processing || !emails.trim()}>
							{processing ? $tr('emailVerifier.buttons.verifying') : $tr('emailVerifier.buttons.verify')}
						</button>
						<button class="clear-btn" onclick={clearAll} disabled={processing}>
							{$tr('emailVerifier.buttons.clear')}
						</button>
					</div>
				</div>

				<div class="section-card">
					<h3 class="section-title" style="font-size: 0.85rem;">{$tr('emailVerifier.examples.title')}</h3>
					<div class="examples-list">
						<button class="example-item" onclick={() => { emails = 'test@gmail.com'; }}>
							<span class="example-name">test@gmail.com</span>
							<span class="example-desc">{$tr('emailVerifier.examples.valid')}</span>
						</button>
						<button class="example-item" onclick={() => { emails = 'user@mailinator.com'; }}>
							<span class="example-name">user@mailinator.com</span>
							<span class="example-desc">{$tr('emailVerifier.examples.disposable')}</span>
						</button>
						<button class="example-item" onclick={() => { emails = 'admin@example.com'; }}>
							<span class="example-name">admin@example.com</span>
							<span class="example-desc">{$tr('emailVerifier.examples.role')}</span>
						</button>
						<button class="example-item" onclick={() => { emails = 'invalid-email'; }}>
							<span class="example-name">invalid-email</span>
							<span class="example-desc">{$tr('emailVerifier.examples.invalid')}</span>
						</button>
					</div>
				</div>
			</div>

			<div class="result-section">
				{#if error}
					<div class="section-card">
						<div class="error-banner">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					</div>
				{:else if result}
					<div class="section-card">
						<div class="result-summary" style="background: {result.invalid_count > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'}; border-left: 3px solid {result.invalid_count > 0 ? '#ef4444' : '#10b981'};">
							{result.summary}
						</div>

						<div class="stat-grid">
							<div class="stat-card">
								<div class="stat-value" style="color: #a855f7">{result.total_checked}</div>
								<div class="stat-label">{$tr('emailVerifier.result.total')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #10b981">{result.valid_count}</div>
								<div class="stat-label">{$tr('emailVerifier.result.valid')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #facc15">{result.risky_count}</div>
								<div class="stat-label">{$tr('emailVerifier.result.risky')}</div>
							</div>
							<div class="stat-card">
								<div class="stat-value" style="color: #ef4444">{result.invalid_count}</div>
								<div class="stat-label">{$tr('emailVerifier.result.invalid')}</div>
							</div>
						</div>

						<div class="sub-tabs">
							<button class="sub-tab {activeResultTab === 'overview' ? 'active' : ''}" onclick={() => activeResultTab = 'overview'}>
								{$tr('emailVerifier.result.tabOverview')}
							</button>
							<button class="sub-tab {activeResultTab === 'details' ? 'active' : ''}" onclick={() => activeResultTab = 'details'}>
								{$tr('emailVerifier.result.tabDetails')}
							</button>
							<button class="sub-tab {activeResultTab === 'security' ? 'active' : ''}" onclick={() => activeResultTab = 'security'}>
								{$tr('emailVerifier.result.tabSecurity')}
							</button>
						</div>

						{#if activeResultTab === 'overview'}
							<div class="email-list">
								{#each result.results as entry}
									<button class="email-item" style="border-left: 3px solid {getRiskColor(entry.risk_level)}" onclick={() => selectedEntry = selectedEntry?.email === entry.email ? null : entry}>
										<span class="status-icon">{getStatusIcon(entry.status)}</span>
										<div class="email-info">
											<span class="email-addr">{entry.email}</span>
											<span class="email-detail">{entry.details}</span>
										</div>
										<div class="email-badges">
											<span class="risk-badge" style="background: {getRiskBg(entry.risk_level)}; color: {getRiskColor(entry.risk_level)}">
												{Math.round(entry.risk_score)}
											</span>
											{#if entry.mx_records_found}
												<span class="badge-ok">MX</span>
											{:else}
												<span class="badge-err">No MX</span>
											{/if}
											{#if entry.is_disposable}
												<span class="badge-warn">{$tr('emailVerifier.result.disposable')}</span>
											{/if}
											{#if entry.is_role_account}
												<span class="badge-info">{$tr('emailVerifier.result.role')}</span>
											{/if}
										</div>
									</button>
								{/each}
							</div>
						{:else if activeResultTab === 'details'}
							{#if selectedEntry}
								<div class="detail-card">
									<div class="detail-header">
										<span class="detail-icon">{getStatusIcon(selectedEntry.status)}</span>
										<span class="detail-email">{selectedEntry.email}</span>
										<span class="risk-badge" style="background: {getRiskBg(selectedEntry.risk_level)}; color: {getRiskColor(selectedEntry.risk_level)}">
											{selectedEntry.risk_level.toUpperCase()} ({Math.round(selectedEntry.risk_score)})
										</span>
									</div>
									<div class="detail-grid">
										<div class="detail-item">
											<span class="detail-label">{$tr('emailVerifier.result.localPart')}</span>
											<span class="detail-value">{selectedEntry.local_part}</span>
										</div>
										<div class="detail-item">
											<span class="detail-label">{$tr('emailVerifier.result.domain')}</span>
											<span class="detail-value">{selectedEntry.domain}</span>
										</div>
										<div class="detail-item">
											<span class="detail-label">{$tr('emailVerifier.result.format')}</span>
											<span class="detail-value" style="color: {selectedEntry.is_valid_format ? '#10b981' : '#ef4444'}">
												{selectedEntry.is_valid_format ? '✓' : '✗'}
											</span>
										</div>
										<div class="detail-item">
											<span class="detail-label">MX</span>
											<span class="detail-value" style="color: {selectedEntry.mx_records_found ? '#10b981' : '#ef4444'}">
												{selectedEntry.mx_records_found ? '✓' : '✗'}
											</span>
										</div>
										{#if selectedEntry.smtp_reachable !== null}
											<div class="detail-item">
												<span class="detail-label">SMTP</span>
												<span class="detail-value" style="color: {selectedEntry.smtp_reachable ? '#10b981' : '#ef4444'}">
													{selectedEntry.smtp_reachable ? '✓' : '✗'}
												</span>
											</div>
										{/if}
										{#if selectedEntry.is_catch_all !== null}
											<div class="detail-item">
												<span class="detail-label">Catch-All</span>
												<span class="detail-value" style="color: {selectedEntry.is_catch_all ? '#facc15' : '#10b981'}">
													{selectedEntry.is_catch_all ? '✓' : '✗'}
												</span>
											</div>
										{/if}
										<div class="detail-item">
											<span class="detail-label">{$tr('emailVerifier.result.disposable')}</span>
											<span class="detail-value" style="color: {selectedEntry.is_disposable ? '#facc15' : '#10b981'}">
												{selectedEntry.is_disposable ? '✓' : '✗'}
											</span>
										</div>
										<div class="detail-item">
											<span class="detail-label">{$tr('emailVerifier.result.role')}</span>
											<span class="detail-value" style="color: {selectedEntry.is_role_account ? '#facc15' : '#10b981'}">
												{selectedEntry.is_role_account ? '✓' : '✗'}
											</span>
										</div>
									</div>
									{#if selectedEntry.mx_records.length > 0}
										<div class="detail-section">
											<span class="detail-section-title">MX {$tr('emailVerifier.result.records')}</span>
											<div class="mx-list">
												{#each selectedEntry.mx_records as mx}
													<span class="mx-tag">{mx}</span>
												{/each}
											</div>
										</div>
									{/if}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">👆</div>
									<p>{$tr('emailVerifier.result.selectEntry')}</p>
								</div>
							{/if}
						{:else if activeResultTab === 'security'}
							<div class="security-overview">
								{#each result.results as entry}
									<div class="security-item" style="border-left: 3px solid {getRiskColor(entry.risk_level)}">
										<div class="security-header">
											<span class="security-email">{entry.email}</span>
											<span class="risk-badge" style="background: {getRiskBg(entry.risk_level)}; color: {getRiskColor(entry.risk_level)}">
												{entry.risk_level.toUpperCase()}
											</span>
										</div>
										<div class="security-grid">
											<div class="security-check">
												<span class="check-label">SPF</span>
												{#if entry.spf_record}
													<span class="check-pass">✓</span>
												{:else}
													<span class="check-fail">✗</span>
												{/if}
											</div>
											<div class="security-check">
												<span class="check-label">DKIM</span>
												{#if entry.dkim_record}
													<span class="check-pass">✓</span>
												{:else}
													<span class="check-fail">✗</span>
												{/if}
											</div>
											<div class="security-check">
												<span class="check-label">DMARC</span>
												{#if entry.dmarc_record}
													<span class="check-pass">✓</span>
												{:else}
													<span class="check-fail">✗</span>
												{/if}
											</div>
										</div>
										{#if entry.spf_record}
											<div class="dns-record">
												<span class="dns-label">SPF:</span>
												<span class="dns-value">{entry.spf_record}</span>
											</div>
										{/if}
										{#if entry.dkim_record}
											<div class="dns-record">
												<span class="dns-label">DKIM:</span>
												<span class="dns-value">{entry.dkim_record}</span>
											</div>
										{/if}
										{#if entry.dmarc_record}
											<div class="dns-record">
												<span class="dns-label">DMARC:</span>
												<span class="dns-value">{entry.dmarc_record}</span>
											</div>
										{/if}
										{#if entry.breach_count !== null && entry.breach_count > 0}
											<div class="breach-warning">
												🔓 {$tr('emailVerifier.result.breachFound').replace('{count}', entry.breach_count.toString())}
											</div>
										{/if}
									</div>
								{/each}
							</div>
						{/if}
					</div>
				{:else}
					<div class="section-card">
						<div class="empty-state">
							<div class="empty-icon">📧</div>
							<p>{$tr('emailVerifier.result.empty')}</p>
							<p class="empty-sub">{$tr('emailVerifier.result.emptySub')}</p>
						</div>
					</div>
				{/if}
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="email_verifier" toolName={$tr('emailVerifier.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="email_verifier" />
		</div>
	{/if}
</div>

<style>
	.nd-page { padding: 1.25rem; max-width: 1200px; margin: 0 auto; }
	.page-header { margin-bottom: 1.25rem; }
	.header-left { display: flex; flex-direction: column; }
	.back-link { color: #94a3b8; text-decoration: none; font-size: 0.8rem; margin-bottom: 0.25rem; }
	.back-link:hover { color: #c4b5fd; }
	.page-title { font-size: 1.4rem; font-weight: 700; margin: 0.25rem 0; color: #e2e8f0; }
	.page-subtitle { color: #94a3b8; font-size: 0.85rem; margin: 0; }

	.tabs { display: flex; gap: 0.25rem; margin-bottom: 1rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.625rem; padding: 0.25rem; border: 1px solid rgba(148, 163, 184, 0.1); }
	.tab-btn { flex: 1; padding: 0.5rem 1rem; border: none; border-radius: 0.5rem; background: transparent; cursor: pointer; font-size: 0.85rem; color: #94a3b8; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.35rem; }
	.tab-btn.active { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3); }
	.tab-btn:hover:not(.active) { background: rgba(148, 163, 184, 0.1); color: #e2e8f0; }
	.tab-icon { font-size: 0.9rem; }

	.content-grid { display: grid; grid-template-columns: 380px 1fr; gap: 1rem; }
	.input-section { display: flex; flex-direction: column; gap: 1rem; }
	.result-section { min-width: 0; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; margin: 0 0 0.75rem; color: #e2e8f0; }
	.section-desc { font-size: 0.8rem; color: #94a3b8; margin: 0 0 0.75rem; }

	.form-group { margin-bottom: 0.75rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.35rem; font-weight: 500; }
	.form-textarea { width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.8); color: #e2e8f0; font-size: 0.85rem; box-sizing: border-box; resize: vertical; font-family: 'SF Mono', 'Fira Code', monospace; }
	.form-textarea:focus { outline: none; border-color: rgba(168, 85, 247, 0.4); box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.1); }
	.form-textarea::placeholder { color: #64748b; }

	.chip-group { display: flex; flex-wrap: wrap; gap: 0.35rem; }
	.target-chip { display: flex; align-items: center; gap: 0.25rem; padding: 0.25rem 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.6); cursor: pointer; font-size: 0.75rem; color: #94a3b8; transition: all 0.2s; }
	.target-chip.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }
	.target-chip input[type="checkbox"] { accent-color: #a855f7; width: 0.75rem; height: 0.75rem; }

	.btn-group { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
	.action-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 0.5rem; background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }
	.action-btn:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.action-btn:disabled { opacity: 0.5; cursor: not-allowed; }
	.clear-btn { padding: 0.6rem 1rem; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 0.5rem; background: rgba(15, 23, 42, 0.6); color: #94a3b8; font-size: 0.85rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
	.clear-btn:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.clear-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.examples-list { display: flex; flex-direction: column; gap: 0.35rem; }
	.example-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.4rem; background: rgba(15, 23, 42, 0.4); cursor: pointer; transition: all 0.2s; }
	.example-item:hover { border-color: rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.05); }
	.example-name { font-size: 0.8rem; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.example-desc { font-size: 0.7rem; color: #94a3b8; }

	.result-summary { padding: 0.75rem 1rem; border-radius: 0.5rem; margin-bottom: 0.75rem; font-size: 0.85rem; color: #e2e8f0; }

	.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; margin-bottom: 0.75rem; }
	.stat-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 0.6rem; text-align: center; }
	.stat-value { font-size: 1.25rem; font-weight: 700; }
	.stat-label { font-size: 0.7rem; color: #94a3b8; margin-top: 0.15rem; }

	.sub-tabs { display: flex; gap: 0.2rem; margin-bottom: 0.75rem; background: rgba(15, 23, 42, 0.6); border-radius: 0.5rem; padding: 0.2rem; }
	.sub-tab { flex: 1; padding: 0.35rem 0.75rem; border: none; border-radius: 0.375rem; background: transparent; cursor: pointer; font-size: 0.8rem; color: #94a3b8; transition: all 0.2s; }
	.sub-tab.active { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }
	.sub-tab:hover:not(.active) { color: #e2e8f0; }

	.email-list { max-height: 500px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.25rem; }
	.email-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; cursor: pointer; transition: all 0.2s; border: none; width: 100%; text-align: left; color: inherit; }
	.email-item:hover { background: rgba(168, 85, 247, 0.05); }
	.status-icon { font-size: 1rem; flex-shrink: 0; }
	.email-info { flex: 1; min-width: 0; }
	.email-addr { font-weight: 500; font-size: 0.85rem; display: block; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.email-detail { font-size: 0.75rem; color: #94a3b8; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.email-badges { display: flex; gap: 0.25rem; flex-shrink: 0; align-items: center; }
	.risk-badge { padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; }
	.badge-ok { padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.65rem; background: rgba(16, 185, 129, 0.15); color: #10b981; }
	.badge-err { padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.65rem; background: rgba(239, 68, 68, 0.15); color: #ef4444; }
	.badge-warn { padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.65rem; background: rgba(250, 204, 21, 0.15); color: #facc15; }
	.badge-info { padding: 0.1rem 0.35rem; border-radius: 0.25rem; font-size: 0.65rem; background: rgba(96, 165, 250, 0.15); color: #60a5fa; }

	.detail-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.5rem; padding: 1rem; }
	.detail-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; padding-bottom: 0.75rem; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
	.detail-icon { font-size: 1.2rem; }
	.detail-email { font-size: 1rem; font-weight: 600; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; margin-bottom: 0.75rem; }
	.detail-item { display: flex; justify-content: space-between; align-items: center; padding: 0.35rem 0.5rem; background: rgba(15, 23, 42, 0.4); border-radius: 0.3rem; }
	.detail-label { font-size: 0.75rem; color: #94a3b8; }
	.detail-value { font-size: 0.8rem; font-weight: 500; }
	.detail-section { margin-top: 0.5rem; }
	.detail-section-title { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.35rem; }
	.mx-list { display: flex; flex-wrap: wrap; gap: 0.25rem; }
	.mx-tag { padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; background: rgba(168, 85, 247, 0.1); color: #c4b5fd; border: 1px solid rgba(168, 85, 247, 0.2); }

	.security-overview { display: flex; flex-direction: column; gap: 0.5rem; max-height: 500px; overflow-y: auto; }
	.security-item { background: rgba(15, 23, 42, 0.4); border-radius: 0.4rem; padding: 0.75rem; }
	.security-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
	.security-email { font-size: 0.85rem; font-weight: 500; color: #e2e8f0; font-family: 'SF Mono', 'Fira Code', monospace; }
	.security-grid { display: flex; gap: 1rem; margin-bottom: 0.5rem; }
	.security-check { display: flex; align-items: center; gap: 0.25rem; }
	.check-label { font-size: 0.75rem; color: #94a3b8; font-weight: 500; }
	.check-pass { color: #10b981; font-weight: 700; }
	.check-fail { color: #ef4444; font-weight: 700; }
	.dns-record { display: flex; gap: 0.35rem; padding: 0.25rem 0; font-size: 0.7rem; }
	.dns-label { color: #94a3b8; font-weight: 600; flex-shrink: 0; }
	.dns-value { color: #c4b5fd; word-break: break-all; font-family: 'SF Mono', 'Fira Code', monospace; }
	.breach-warning { padding: 0.35rem 0.5rem; border-radius: 0.3rem; background: rgba(239, 68, 68, 0.1); color: #f87171; font-size: 0.8rem; margin-top: 0.35rem; }

	.error-banner { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 0.5rem; }
	.error-icon { font-size: 1.1rem; }
	.error-text { color: #f87171; font-size: 0.85rem; }

	.empty-state { text-align: center; padding: 2.5rem 1rem; color: #94a3b8; }
	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
	.empty-state p { margin: 0; font-size: 0.9rem; }
	.empty-sub { font-size: 0.8rem !important; color: #64748b !important; margin-top: 0.35rem !important; }

	@media (max-width: 768px) {
		.content-grid { grid-template-columns: 1fr; }
		.stat-grid { grid-template-columns: repeat(2, 1fr); }
	}
</style>
