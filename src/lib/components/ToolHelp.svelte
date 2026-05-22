<script lang="ts">
	import { tr } from '$lib/i18n';
	export let toolType: string;

	interface HelpSection {
		title: string;
		content: string;
	}

	interface ToolHelpInfo {
		tool_type: string;
		tool_name: string;
		description: string;
		usage: string;
		sections: HelpSection[];
	}

	let helpInfo: ToolHelpInfo | null = null;
	let loading = false;
	let error = '';

	async function loadHelp() {
		loading = true;
		error = '';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			helpInfo = await invoke<ToolHelpInfo>('get_tool_help', { toolType });
		} catch (e: any) {
			error = e.toString();
		} finally {
			loading = false;
		}
	}

	loadHelp();
</script>

<div class="tool-help">
	{#if loading}
		<div class="help-loading">
			<div class="spinner"></div>
			<span>{$tr('common.loading')}</span>
		</div>
	{:else if error}
		<div class="help-error">⚠️ {error}</div>
	{:else if helpInfo}
		<div class="help-content">
			<div class="help-header">
				<h3 class="help-title">📖 {helpInfo.tool_name}</h3>
			</div>
			<div class="help-description">{helpInfo.description}</div>
			<div class="help-usage">
				<div class="usage-label">{$tr('toolHelp.usageLabel')}</div>
				<div class="usage-text">{helpInfo.usage}</div>
			</div>
			{#if helpInfo.sections.length > 0}
				<div class="help-sections">
					{#each helpInfo.sections as section}
						<div class="help-section">
							<div class="section-title">💡 {section.title}</div>
							<div class="section-content">{section.content}</div>
						</div>
					{/each}
				</div>
			{/if}
			<div class="help-footer">
				<div class="footer-tip">{$tr('toolHelp.legalWarning')}</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.tool-help { padding: 4px; }
	.help-loading { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 30px; color: var(--text-secondary); }
	.spinner { width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.help-error { padding: 8px 12px; background: rgba(239,68,68,0.1); border-radius: 8px; color: #ef4444; font-size: 0.85rem; }
	.help-content { display: flex; flex-direction: column; gap: 12px; }
	.help-header { margin-bottom: 4px; }
	.help-title { font-size: 1.1rem; margin: 0; }
	.help-description { font-size: 0.9rem; color: var(--text-secondary); line-height: 1.5; padding: 8px 12px; background: rgba(168,85,247,0.08); border-radius: 8px; }
	.help-usage { padding: 10px 12px; background: var(--bg-primary); border-radius: 8px; border: 1px solid var(--border); }
	.usage-label { font-weight: 600; font-size: 0.9rem; margin-bottom: 6px; }
	.usage-text { font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; }
	.help-sections { display: flex; flex-direction: column; gap: 8px; }
	.help-section { padding: 10px 12px; background: var(--bg-primary); border-radius: 8px; border: 1px solid var(--border); }
	.section-title { font-weight: 600; font-size: 0.85rem; margin-bottom: 4px; }
	.section-content { font-size: 0.82rem; color: var(--text-secondary); line-height: 1.6; }
	.help-footer { margin-top: 8px; }
	.footer-tip { font-size: 0.78rem; color: #f59e0b; padding: 8px 12px; background: rgba(245,158,11,0.08); border-radius: 8px; text-align: center; }
</style>
