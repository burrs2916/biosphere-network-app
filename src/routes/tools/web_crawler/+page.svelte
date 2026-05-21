<script lang="ts">
	import { tr } from '$lib/i18n';
	import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

	interface CrawledLink {
		url: string;
		status_code: number;
		title: string | null;
		depth: number;
		content_type: string | null;
		response_time_ms: number | null;
		word_count: number | null;
		score: number | null;
	}

	interface ResourceInfo {
		url: string;
		resource_type: string;
		size: number | null;
		source_page: string | null;
		score: number | null;
	}

	interface ApiEndpoint {
		url: string;
		method: string;
		source: string;
	}

	interface PageMetadata {
		title: string | null;
		description: string | null;
		keywords: string | null;
		og_title: string | null;
		og_description: string | null;
		og_image: string | null;
		og_video: string | null;
		og_audio: string | null;
		og_type: string | null;
		og_site_name: string | null;
		twitter_card: string | null;
		twitter_title: string | null;
		twitter_description: string | null;
		twitter_image: string | null;
		canonical: string | null;
		generator: string | null;
		author: string | null;
		viewport: string | null;
		robots: string | null;
	}

	interface DirEntryInfo {
		path: string;
		full_url: string;
		status_code: number;
		content_length: number | null;
		content_type: string | null;
		is_directory: boolean;
	}

	interface AntibotDetection {
		detected: boolean;
		protection_type: string | null;
		confidence: number;
		details: string[];
	}

	interface SecurityInfo {
		has_https: boolean;
		has_hsts: boolean;
		has_csp: boolean;
		has_x_frame_options: boolean;
		has_x_content_type_options: boolean;
		server_header: string | null;
		powered_by_header: string | null;
		security_score: number;
		csp_directives: string | null;
		has_strict_transport: boolean;
		has_x_xss_protection: boolean;
		has_referrer_policy: boolean;
		has_permissions_policy: boolean;
	}

	interface PopupDetection {
		detected: boolean;
		popup_types: string[];
		confidence: number;
		details: string[];
	}

	interface PaywallDetection {
		detected: boolean;
		paywall_type: string | null;
		confidence: number;
		details: string[];
		hidden_content_detected: boolean;
	}

	interface WebCrawlerResult {
		start_url: string;
		pages_crawled: number;
		total_links: number;
		links: CrawledLink[];
		emails: string[];
		js_files: ResourceInfo[];
		comments: string[];
		images: ResourceInfo[];
		css_files: ResourceInfo[];
		fonts: ResourceInfo[];
		documents: ResourceInfo[];
		videos: ResourceInfo[];
		audio_files: ResourceInfo[];
		api_endpoints: ApiEndpoint[];
		metadata: PageMetadata;
		technologies: string[];
		technology_details: TechnologyDetail[];
		directory_entries: DirEntryInfo[];
		summary: string;
		antibot_detection: AntibotDetection | null;
		subdomains: string[];
		security_info: SecurityInfo;
		paywall_detection: PaywallDetection | null;
		ssl_cert_info: SslCertInfo | null;
		popup_detection: PopupDetection | null;
		markdown_content: string | null;
	}

	interface TechnologyDetail {
		name: string;
		category: string;
		version: string | null;
		confidence: number;
		evidence: string[];
		icon: string;
	}

	interface SslCertInfo {
		subject: string | null;
		issuer: string | null;
		not_before: string | null;
		not_after: string | null;
		is_expired: boolean;
		days_remaining: number | null;
		fingerprint_sha256: string | null;
		subject_alt_names: string[];
	}

	interface DownloadResult {
		url: string;
		file_path: string;
		file_size: number;
		success: boolean;
		error: string | null;
	}

	interface BatchDownloadResult {
		total: number;
		success_count: number;
		failed_count: number;
		results: DownloadResult[];
		save_dir: string;
		paywall_detected: boolean | null;
		download_limit_detected: boolean | null;
	}

	let url = $state('');
	let activeMainTab = $state('analyze');
	let historyComponent: ToolHistory = $state(null!);
	let maxDepth = $state(2);
	let maxPages = $state(100);
	let timeout = $state(15);
	let concurrentRequests = $state(5);
	let followExternal = $state(false);
	let extractEmails = $state(true);
	let extractJs = $state(true);
	let extractComments = $state(true);
	let extractImages = $state(true);
	let extractCss = $state(true);
	let extractFonts = $state(false);
	let extractDocuments = $state(true);
	let extractVideos = $state(true);
	let extractAudio = $state(true);
	let extractApiEndpoints = $state(true);
	let extractMetadata = $state(true);
	let scanDirectories = $state(false);
	let crawlMode = $state('full');
	let result: WebCrawlerResult | null = $state(null);
	let error = $state('');
	let processing = $state(false);
	let activeResultTab = $state('overview');
	let linkFilter = $state('all');
	let searchQuery = $state('');
	let downloadingUrls = $state<string[]>([]);
	let downloadingAll = $state(false);
	let downloadProgress = $state({ current: 0, total: 0, currentFile: '' });
	let downloadLog = $state<DownloadResult[]>([]);
	let downloadMode = $state('by_type');
	let maxConcurrent = $state(5);
	let maxRetries = $state(3);
	let retryDelay = $state(1000);
	let showDownloadConfig = $state(false);
	let exportFormat = $state('json');
	let exporting = $state(false);
	let proxyUrl = $state('');
	let keywords = $state('');
	let detectAntibot = $state(true);
	let crawlStrategy = $state('bfs');
	let requestDelayMs = $state(200);
	let parseCssResources = $state(true);
	let normalizeUrls = $state(true);
	let mirrorMode = $state(false);
	let fullSiteDownloading = $state(false);
	let fullSiteDepth = $state(3);
	let fullSiteMaxPages = $state(500);
	let fullSiteFollowExternal = $state(false);
	let cookies = $state('');
	let customHeaders = $state('');
	let maxDownloadCount = $state(0);
	let priorityOrder = $state('video,audio,image,document,font,css,js');
	let showAuthConfig = $state(false);
	let crawlIframes = $state(true);
	let urlFilterPatterns = $state('');
	let urlExcludePatterns = $state('');
	let cacheEnabled = $state(false);
	let cacheTtlSeconds = $state(3600);
	let proxyPoolProxies = $state('');
	let proxyPoolRotationMode = $state('round_robin');
	let showAdvancedConfig = $state(false);

	function isDownloading(url: string): boolean {
		return downloadingUrls.includes(url);
	}

	function addDownloading(url: string) {
		if (!downloadingUrls.includes(url)) {
			downloadingUrls = [...downloadingUrls, url];
		}
	}

	function removeDownloading(url: string) {
		downloadingUrls = downloadingUrls.filter(u => u !== url);
	}

	function getStatusColor(code: number): string {
		if (code >= 200 && code < 300) return '#22c55e';
		if (code >= 300 && code < 400) return '#3b82f6';
		if (code >= 400 && code < 500) return '#f59e0b';
		return '#ef4444';
	}

	function getMethodColor(method: string): string {
		switch (method.toUpperCase()) {
			case 'GET': return '#22c55e';
			case 'POST': return '#3b82f6';
			case 'PUT': return '#f59e0b';
			case 'DELETE': return '#ef4444';
			case 'PATCH': return '#a855f7';
			default: return '#94a3b8';
		}
	}

	function getResourceTypeIcon(type: string): string {
		switch (type) {
			case 'javascript': case 'esmodule': return '📜';
			case 'stylesheet': case 'css-import': return '🎨';
			case 'svg': case 'png': case 'jpeg': case 'webp': case 'gif': case 'ico': case 'image': case 'responsive': case 'background': case 'og-image': case 'css-image': return '🖼️';
			case 'woff': case 'woff2': case 'ttf': case 'otf': case 'eot': case 'webfont': case 'css-font': return '🔤';
			case 'pdf': return '📄';
			case 'doc': case 'docx': return '📝';
			case 'xls': case 'xlsx': return '📊';
			case 'zip': case 'rar': return '📦';
			case 'mp4': case 'webm': case 'ogg': case 'avi': case 'mov': case 'flv': case 'wmv': case 'hls': case 'ts': case 'video': return '🎬';
			case 'mp3': case 'wav': case 'flac': case 'aac': case 'm4a': case 'wma': case 'opus': case 'oga': case 'audio': return '🎵';
			case 'embed': return '📺';
			default: return '📎';
		}
	}

	function getTechIcon(tech: string): string {
		const lower = tech.toLowerCase();
		if (lower.includes('react')) return '⚛️';
		if (lower.includes('vue')) return '💚';
		if (lower.includes('angular')) return '🔴';
		if (lower.includes('next')) return '▲';
		if (lower.includes('nuxt')) return '💚';
		if (lower.includes('svelte')) return '🔥';
		if (lower.includes('wordpress')) return '📝';
		if (lower.includes('bootstrap')) return '🅱️';
		if (lower.includes('tailwind')) return '🌊';
		if (lower.includes('cloudflare')) return '☁️';
		if (lower.includes('google')) return '🔍';
		if (lower.includes('stripe')) return '💳';
		if (lower.includes('paypal')) return '💰';
		return '🔧';
	}

	function getFilteredLinks(): CrawledLink[] {
		if (!result) return [];
		let links = result.links;
		if (linkFilter === 'success') links = links.filter(l => l.status_code >= 200 && l.status_code < 300);
		else if (linkFilter === 'redirect') links = links.filter(l => l.status_code >= 300 && l.status_code < 400);
		else if (linkFilter === 'error') links = links.filter(l => l.status_code >= 400);
		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase();
			links = links.filter(l => l.url.toLowerCase().includes(q) || (l.title && l.title.toLowerCase().includes(q)));
		}
		return links;
	}

	function getTotalResources(): number {
		if (!result) return 0;
		return result.js_files.length + result.images.length + result.css_files.length + result.fonts.length + result.documents.length + result.videos.length + result.audio_files.length;
	}

	function getAllResourceUrls(): string[] {
		if (!result) return [];
		return [
			...result.js_files.map(r => r.url),
			...result.images.map(r => r.url),
			...result.css_files.map(r => r.url),
			...result.fonts.map(r => r.url),
			...result.documents.map(r => r.url),
			...result.videos.map(r => r.url),
			...result.audio_files.map(r => r.url),
		];
	}

	function formatFileSize(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
	}

	function getCrawlModeLabel(mode: string): string {
		switch (mode) {
			case 'quick': return $tr('webCrawler.modeQuick');
			case 'balanced': return $tr('webCrawler.modeBalanced');
			case 'full': return $tr('webCrawler.modeFull');
			case 'deep': return $tr('webCrawler.modeDeep');
			default: return mode;
		}
	}

	function applyCrawlMode(mode: string) {
		crawlMode = mode;
		switch (mode) {
			case 'quick':
				maxDepth = 1; maxPages = 20; concurrentRequests = 3;
				break;
			case 'balanced':
				maxDepth = 2; maxPages = 50; concurrentRequests = 5;
				break;
			case 'full':
				maxDepth = 3; maxPages = 100; concurrentRequests = 8;
				break;
			case 'deep':
				maxDepth = 5; maxPages = 300; concurrentRequests = 10;
				break;
		}
	}

	async function downloadSingle(resourceUrl: string) {
		addDownloading(resourceUrl);
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const saveDir = await open({ directory: true, multiple: false, title: $tr('webCrawler.selectSaveDir') });
			if (!saveDir) {
				removeDownloading(resourceUrl);
				return;
			}
			const dlResult = await invoke<DownloadResult>('download_resource_command', {
				url: resourceUrl,
				saveDir: saveDir as string,
			});
			if (dlResult.success) {
				downloadLog = [...downloadLog, dlResult];
			}
		} catch (e: any) {
			console.error('Download failed:', e);
		} finally {
			removeDownloading(resourceUrl);
		}
	}

	async function downloadAll() {
		const urls = getAllResourceUrls();
		if (urls.length === 0) return;
		downloadingAll = true;
		downloadProgress = { current: 0, total: urls.length, currentFile: '' };
		downloadLog = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const saveDir = await open({ directory: true, multiple: false, title: $tr('webCrawler.selectSaveDir') });
			if (!saveDir) {
				downloadingAll = false;
				return;
			}
			const batchResult = await invoke<{ total: number; success_count: number; failed_count: number; results: DownloadResult[]; save_dir: string; paywall_detected: boolean | null; download_limit_detected: boolean | null }>('download_resources_batch_with_config_command', {
				urls,
				saveDir: saveDir as string,
				downloadMode,
				maxConcurrent,
				maxRetries,
				retryDelayMs: retryDelay,
				mirrorMode: false,
				cookies: cookies || null,
				customHeaders: customHeaders || null,
				maxDownloadCount: maxDownloadCount > 0 ? maxDownloadCount : null,
			});
			downloadLog = batchResult.results;
		} catch (e: any) {
			console.error('Batch download failed:', e);
		} finally {
			downloadingAll = false;
			downloadProgress = { current: 0, total: 0, currentFile: '' };
		}
	}

	async function downloadSite() {
		if (!result) return;
		downloadingAll = true;
		downloadLog = [];
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const saveDir = await open({ directory: true, multiple: false, title: $tr('webCrawler.selectSaveDir') });
			if (!saveDir) {
				downloadingAll = false;
				return;
			}
			const batchResult = await invoke<{ total: number; success_count: number; failed_count: number; results: DownloadResult[]; save_dir: string }>('download_site_command', {
				config: {
					save_dir: saveDir as string,
					download_mode: downloadMode,
					max_concurrent: maxConcurrent,
					max_retries: maxRetries,
					retry_delay_ms: retryDelay,
					include_images: true,
					include_videos: true,
					include_audio: true,
					include_css: true,
					include_js: true,
					include_fonts: true,
					include_documents: true,
					mirror_mode: mirrorMode,
					proxy_url: proxyUrl,
					cookies: cookies,
					custom_headers: customHeaders,
					max_download_count: maxDownloadCount,
					priority_order: priorityOrder,
					proxy_pool: {
						proxies: proxyPoolProxies.split('\n').map(s => s.trim()).filter(s => s.length > 0),
						rotation_mode: proxyPoolRotationMode,
						retry_on_proxy_error: true,
						validate_proxies: false,
					},
					cache: {
						enabled: cacheEnabled,
						cache_dir: '',
						ttl_seconds: cacheTtlSeconds,
						respect_cache_control: true,
					},
					rewrite_urls: true,
				},
				crawlResult: result,
			});
			downloadLog = batchResult.results;
		} catch (e: any) {
			console.error('Site download failed:', e);
		} finally {
			downloadingAll = false;
		}
	}

	async function downloadByType(type: string) {
		let urls: string[] = [];
		if (!result) return;
		switch (type) {
			case 'js': urls = result.js_files.map(r => r.url); break;
			case 'images': urls = result.images.map(r => r.url); break;
			case 'css': urls = result.css_files.map(r => r.url); break;
			case 'fonts': urls = result.fonts.map(r => r.url); break;
			case 'docs': urls = result.documents.map(r => r.url); break;
			case 'videos': urls = result.videos.map(r => r.url); break;
			case 'audio': urls = result.audio_files.map(r => r.url); break;
		}
		if (urls.length === 0) return;
		downloadingAll = true;
		downloadProgress = { current: 0, total: urls.length, currentFile: '' };
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const saveDir = await open({ directory: true, multiple: false, title: $tr('webCrawler.selectSaveDir') });
			if (!saveDir) {
				downloadingAll = false;
				return;
			}
			const batchResult = await invoke<{ total: number; success_count: number; failed_count: number; results: DownloadResult[]; save_dir: string }>('download_resources_batch_with_config_command', {
				urls,
				saveDir: saveDir as string,
				downloadMode,
				maxConcurrent,
				maxRetries,
				retryDelayMs: retryDelay,
				mirrorMode: false,
				cookies: cookies || null,
				customHeaders: customHeaders || null,
				maxDownloadCount: maxDownloadCount > 0 ? maxDownloadCount : null,
			});
			downloadLog = batchResult.results;
		} catch (e: any) {
			console.error('Batch download failed:', e);
		} finally {
			downloadingAll = false;
			downloadProgress = { current: 0, total: 0, currentFile: '' };
		}
	}

	async function crawl() {
		if (!url.trim()) { error = $tr('webCrawler.error.emptyInput'); return; }
		processing = true; error = ''; result = null;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			result = await invoke<WebCrawlerResult>('crawl_web_command', {
				config: {
					url: url.trim(),
					max_depth: maxDepth,
					max_pages: maxPages,
					timeout,
					follow_external: followExternal,
					extract_emails: extractEmails,
					extract_js: extractJs,
					extract_comments: extractComments,
					extract_images: extractImages,
					extract_css: extractCss,
					extract_fonts: extractFonts,
					extract_documents: extractDocuments,
					extract_videos: extractVideos,
					extract_audio: extractAudio,
					extract_api_endpoints: extractApiEndpoints,
					extract_metadata: extractMetadata,
					scan_directories: scanDirectories,
					respect_robots: true,
					concurrent_requests: concurrentRequests,
					crawl_mode: crawlMode,
					download_mode: downloadMode,
					max_retries: maxRetries,
					retry_delay_ms: retryDelay,
					proxy_url: proxyUrl,
					detect_antibot: detectAntibot,
					keywords: keywords,
					crawl_strategy: crawlStrategy,
					request_delay_ms: requestDelayMs,
					parse_css_resources: parseCssResources,
					normalize_urls: normalizeUrls,
					cookies: cookies,
					custom_headers: customHeaders,
					max_download_count: maxDownloadCount,
					priority_order: priorityOrder,
					crawl_iframes: crawlIframes,
					url_filter_patterns: urlFilterPatterns,
					url_exclude_patterns: urlExcludePatterns,
					proxy_pool: {
						proxies: proxyPoolProxies.split('\n').map(s => s.trim()).filter(s => s.length > 0),
						rotation_mode: proxyPoolRotationMode,
						retry_on_proxy_error: true,
						validate_proxies: false,
					},
					cache: {
						enabled: cacheEnabled,
						cache_dir: '',
						ttl_seconds: cacheTtlSeconds,
						respect_cache_control: true,
					},
				}
			});
			if (result && historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify(result), result.summary, 'completed');
			}
		} catch (e: any) {
			error = e.toString();
			if (historyComponent) {
				await historyComponent.saveHistory(url.trim(), JSON.stringify({ error: e.toString() }), undefined, 'failed');
			}
		} finally { processing = false; }
	}

	async function downloadFullSite() {
		if (!url.trim()) { error = $tr('webCrawler.error.emptyInput'); return; }
		fullSiteDownloading = true; error = '';
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const selected = await open({ directory: true, multiple: false });
			if (!selected) { fullSiteDownloading = false; return; }
			const saveDir = typeof selected === 'string' ? selected : (selected as any).path || String(selected);
			const domain = new URL(url.trim()).hostname;
			const fullSaveDir = `${saveDir}/${domain}_full_site`;
			const downloadResult = await invoke<BatchDownloadResult>('download_full_site_command', {
				startUrl: url.trim(),
				saveDir: fullSaveDir,
				maxDepth: fullSiteDepth,
				maxPages: fullSiteMaxPages,
				maxConcurrent: concurrentRequests,
				followExternal: fullSiteFollowExternal,
			});
			if (downloadResult) {
				result = {
					...result,
					summary: `Full site download: ${downloadResult.success_count} succeeded, ${downloadResult.failed_count} failed. Saved to: ${downloadResult.save_dir}`
				} as any;
			}
		} catch (e: any) {
			error = e.toString();
		} finally { fullSiteDownloading = false; }
	}

	async function exportResult() {
		if (!result) return;
		exporting = true;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const { open } = await import('@tauri-apps/plugin-dialog');
			const savePath = await open({
				directory: true,
				multiple: false,
				title: $tr('webCrawler.selectSaveDir')
			});
			if (!savePath) {
				exporting = false;
				return;
			}
			const ext = exportFormat === 'csv' ? 'csv' : 'json';
			const fileName = `crawl-result-${new Date().toISOString().slice(0, 10)}.${ext}`;
			const content = await invoke<string>('export_crawl_result_command', {
				result,
				config: {
					format: exportFormat,
					save_path: savePath as string,
					include_links: true,
					include_resources: true,
					include_emails: true,
					include_apis: true,
					include_metadata: true,
					include_technologies: true,
					include_directory: true,
					include_security: true,
				}
			});
			const { writeTextFile } = await import('@tauri-apps/plugin-fs');
			await writeTextFile(`${savePath}/${fileName}`, content);
		} catch (e: any) {
			console.error('Export failed:', e);
		} finally {
			exporting = false;
		}
	}

	function getSecurityScoreColor(score: number): string {
		if (score >= 80) return '#22c55e';
		if (score >= 60) return '#eab308';
		if (score >= 40) return '#f97316';
		return '#ef4444';
	}

	function clearAll() {
		url = ''; result = null; error = '';
		linkFilter = 'all'; searchQuery = '';
		activeResultTab = 'overview';
		downloadLog = [];
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !processing && url.trim()) {
			crawl();
		}
	}
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🕷️ {$tr('webCrawler.title')}</h1>
			<p class="page-subtitle">{$tr('webCrawler.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" on:click={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('webCrawler.crawl')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" on:click={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('webCrawler.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" on:click={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('webCrawler.help')}
		</button>
	</div>

	{#if activeMainTab === 'analyze'}
		<div class="content-grid">
			<div class="input-section">
				<div class="section-card">
					<h2 class="section-title">{$tr('webCrawler.configTitle')}</h2>
					<p class="section-desc">{$tr('webCrawler.configDesc')}</p>

					<div class="form-group">
						<label class="form-label">{$tr('webCrawler.targetUrl')}</label>
						<input type="text" bind:value={url} placeholder="https://example.com" class="form-input" disabled={processing} />
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('webCrawler.crawlMode')}</label>
						<div class="mode-grid">
							{#each ['quick', 'balanced', 'full', 'deep'] as mode}
								<button class="mode-btn {crawlMode === mode ? 'active' : ''}" on:click={() => applyCrawlMode(mode)} disabled={processing}>
									<span class="mode-name">{getCrawlModeLabel(mode)}</span>
								</button>
							{/each}
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('webCrawler.maxDepth')}</label>
							<input type="number" bind:value={maxDepth} class="form-input" min="1" max="10" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('webCrawler.maxPages')}</label>
							<input type="number" bind:value={maxPages} class="form-input" min="1" max="500" disabled={processing} />
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">{$tr('webCrawler.timeout')}</label>
							<input type="number" bind:value={timeout} class="form-input" min="5" max="60" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">{$tr('webCrawler.concurrent')}</label>
							<input type="number" bind:value={concurrentRequests} class="form-input" min="1" max="20" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="form-label">{$tr('webCrawler.targetSelection')}</label>
						<div class="target-grid">
							<label class="target-chip {extractEmails ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractEmails} disabled={processing} />
								<span>📧 {$tr('webCrawler.targetEmails')}</span>
							</label>
							<label class="target-chip {extractJs ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractJs} disabled={processing} />
								<span>📜 JS</span>
							</label>
							<label class="target-chip {extractImages ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractImages} disabled={processing} />
								<span>🖼️ {$tr('webCrawler.targetImages')}</span>
							</label>
							<label class="target-chip {extractCss ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractCss} disabled={processing} />
								<span>🎨 CSS</span>
							</label>
							<label class="target-chip {extractFonts ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractFonts} disabled={processing} />
								<span>🔤 {$tr('webCrawler.targetFonts')}</span>
							</label>
							<label class="target-chip {extractDocuments ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractDocuments} disabled={processing} />
								<span>📄 {$tr('webCrawler.targetDocs')}</span>
							</label>
							<label class="target-chip {extractVideos ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractVideos} disabled={processing} />
								<span>🎬 {$tr('webCrawler.targetVideos')}</span>
							</label>
							<label class="target-chip {extractAudio ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractAudio} disabled={processing} />
								<span>🎵 {$tr('webCrawler.targetAudio')}</span>
							</label>
							<label class="target-chip {extractApiEndpoints ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractApiEndpoints} disabled={processing} />
								<span>🔌 API</span>
							</label>
							<label class="target-chip {extractComments ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractComments} disabled={processing} />
								<span>💬 {$tr('webCrawler.targetComments')}</span>
							</label>
							<label class="target-chip {extractMetadata ? 'active' : ''}">
								<input type="checkbox" bind:checked={extractMetadata} disabled={processing} />
								<span>🏷️ {$tr('webCrawler.targetMeta')}</span>
							</label>
							<label class="target-chip {followExternal ? 'active' : ''}">
								<input type="checkbox" bind:checked={followExternal} disabled={processing} />
								<span>🔗 {$tr('webCrawler.targetExternal')}</span>
							</label>
							<label class="target-chip {scanDirectories ? 'active' : ''}">
								<input type="checkbox" bind:checked={scanDirectories} disabled={processing} />
								<span>📁 {$tr('webCrawler.scanDirs')}</span>
							</label>
						</div>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">🌐 Proxy URL</label>
							<input type="text" bind:value={proxyUrl} placeholder="http://proxy:port" class="form-input" disabled={processing} />
						</div>
						<div class="form-group">
							<label class="form-label">🔑 Keywords</label>
							<input type="text" bind:value={keywords} placeholder="api,download,media..." class="form-input" disabled={processing} />
						</div>
					</div>

					<div class="form-group">
						<label class="target-chip {detectAntibot ? 'active' : ''}">
							<input type="checkbox" bind:checked={detectAntibot} disabled={processing} />
							<span>🛡️ {$tr('webCrawler.detectAntibot')}</span>
						</label>
						<label class="target-chip {parseCssResources ? 'active' : ''}">
							<input type="checkbox" bind:checked={parseCssResources} disabled={processing} />
							<span>🎨 CSS Resource Parsing</span>
						</label>
						<label class="target-chip {normalizeUrls ? 'active' : ''}">
							<input type="checkbox" bind:checked={normalizeUrls} disabled={processing} />
							<span>🔗 URL Normalization</span>
						</label>
						<label class="target-chip {mirrorMode ? 'active' : ''}">
							<input type="checkbox" bind:checked={mirrorMode} disabled={processing} />
							<span>🪞 Mirror Mode</span>
						</label>
					</div>

					<div class="form-row">
						<div class="form-group">
							<label class="form-label">📊 Crawl Strategy</label>
							<select bind:value={crawlStrategy} class="form-input" disabled={processing}>
								<option value="bfs">BFS (Breadth-First)</option>
								<option value="dfs">DFS (Depth-First)</option>
								<option value="best_first">Best-First (Scored)</option>
							</select>
						</div>
						<div class="form-group">
							<label class="form-label">⏱️ Request Delay (ms)</label>
							<input type="number" bind:value={requestDelayMs} min="0" max="10000" step="50" class="form-input" disabled={processing} />
						</div>
					</div>

					<div class="button-group">
						<button class="btn-primary" on:click={crawl} disabled={processing || fullSiteDownloading || !url.trim()}>
							{#if processing}<span class="spinner"></span>{$tr('webCrawler.crawling')}{:else}🕷️ {$tr('webCrawler.startCrawl')}{/if}
						</button>
						<button class="btn-accent" on:click={downloadFullSite} disabled={processing || fullSiteDownloading || !url.trim()} title="One-click full site download with local path rewriting">
							{#if fullSiteDownloading}<span class="spinner"></span>Downloading...{:else}⚡ Full Site Download{/if}
						</button>
						<button class="btn-secondary" on:click={clearAll} disabled={processing || fullSiteDownloading}>🗑️</button>
					</div>

					{#if fullSiteDownloading || true}
					<div class="full-site-config" style="margin-top: 8px; padding: 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface);">
						<div style="font-size: 12px; font-weight: 600; margin-bottom: 8px; color: var(--accent);">⚡ Full Site Download Settings</div>
						<div class="form-row">
							<div class="form-group">
								<label class="form-label">📏 Max Depth</label>
								<input type="number" bind:value={fullSiteDepth} min="1" max="20" step="1" class="form-input" disabled={fullSiteDownloading} />
							</div>
							<div class="form-group">
								<label class="form-label">📄 Max Pages</label>
								<input type="number" bind:value={fullSiteMaxPages} min="1" max="10000" step="50" class="form-input" disabled={fullSiteDownloading} />
							</div>
							<div class="form-group">
								<label class="form-label">🔗 Follow External</label>
								<select bind:value={fullSiteFollowExternal} class="form-input" disabled={fullSiteDownloading}>
									<option value={false}>Same Domain Only</option>
									<option value={true}>All Domains</option>
								</select>
							</div>
						</div>
					</div>
					{/if}
				</div>
			</div>

			<div class="result-section">
				<div class="section-card">
					{#if error}
						<div class="error-card">
							<span class="error-icon">⚠️</span>
							<span class="error-text">{error}</span>
						</div>
					{:else if result}
						<div class="result-header">
							<div class="result-domain">
								<h2 class="section-title" style="margin-bottom:0">🕷️ {result.start_url}</h2>
							</div>
							<div class="header-actions">
								<div class="resource-score-badge">
									<span class="score-value">{getTotalResources()}</span>
									<span class="score-label">{$tr('webCrawler.resourcesFound')}</span>
								</div>
								<button class="btn-config-toggle" on:click={() => showDownloadConfig = !showDownloadConfig} title="Download Settings">
									⚙️
								</button>
								<button class="btn-download-site" on:click={downloadSite} disabled={downloadingAll || getTotalResources() === 0}>
									{#if downloadingAll}<span class="spinner-sm"></span>{:else}🌐{/if}
									{$tr('webCrawler.downloadSite')}
								</button>
								<button class="btn-download-all" on:click={downloadAll} disabled={downloadingAll || getTotalResources() === 0}>
									{#if downloadingAll}<span class="spinner-sm"></span>{:else}⬇️{/if}
									{$tr('webCrawler.downloadAll')}
								</button>
								<select bind:value={exportFormat} class="export-select" disabled={exporting}>
									<option value="json">JSON</option>
									<option value="csv">CSV</option>
								</select>
								<button class="btn-export" on:click={exportResult} disabled={exporting || !result}>
									{#if exporting}<span class="spinner-sm"></span>{:else}📤{/if}
									{$tr('webCrawler.export')}
								</button>
							</div>
						</div>

						{#if showDownloadConfig}
							<div class="download-config-panel">
								<div class="config-row">
									<label class="config-label">{$tr('webCrawler.downloadMode')}</label>
									<div class="config-mode-btns">
										<button class="config-mode-btn {downloadMode === 'by_type' ? 'active' : ''}" on:click={() => downloadMode = 'by_type'}>
											📁 {$tr('webCrawler.modeByType')}
										</button>
										<button class="config-mode-btn {downloadMode === 'by_site' ? 'active' : ''}" on:click={() => downloadMode = 'by_site'}>
											🌐 {$tr('webCrawler.modeBySite')}
										</button>
										<button class="config-mode-btn {downloadMode === 'flat' ? 'active' : ''}" on:click={() => downloadMode = 'flat'}>
											📄 {$tr('webCrawler.modeFlat')}
										</button>
									</div>
								</div>
								<div class="config-row">
									<div class="config-field">
										<label class="config-label">{$tr('webCrawler.maxConcurrent')}</label>
										<input type="number" bind:value={maxConcurrent} class="config-input" min="1" max="20" />
									</div>
									<div class="config-field">
										<label class="config-label">{$tr('webCrawler.maxRetries')}</label>
										<input type="number" bind:value={maxRetries} class="config-input" min="0" max="10" />
									</div>
									<div class="config-field">
										<label class="config-label">{$tr('webCrawler.retryDelay')}</label>
										<input type="number" bind:value={retryDelay} class="config-input" min="100" max="10000" step="100" />
									</div>
								</div>
								<div class="config-row">
									<div class="config-field">
										<label class="config-label">🔢 Max Downloads (0=unlimited)</label>
										<input type="number" bind:value={maxDownloadCount} class="config-input" min="0" max="10000" />
									</div>
									<div class="config-field" style="flex: 2;">
										<label class="config-label">🎯 Priority Order</label>
										<input type="text" bind:value={priorityOrder} class="config-input" placeholder="video,audio,image,document,font,css,js" />
									</div>
								</div>
								<div class="config-row">
									<button class="config-mode-btn {showAuthConfig ? 'active' : ''}" on:click={() => showAuthConfig = !showAuthConfig}>
										🔐 Auth & Cookies
									</button>
								</div>
								{#if showAuthConfig}
									<div class="config-row">
										<div class="config-field" style="flex: 1;">
											<label class="config-label">🍪 Cookies</label>
											<input type="text" bind:value={cookies} class="config-input" placeholder="session_id=abc123; token=xyz" />
										</div>
									</div>
									<div class="config-row">
										<div class="config-field" style="flex: 1;">
											<label class="config-label">📋 Custom Headers (one per line, Key: Value)</label>
											<textarea bind:value={customHeaders} class="config-input" style="height: 60px; resize: vertical; font-family: monospace; font-size: 12px;" placeholder={"Authorization: Bearer token123\nX-API-Key: your-api-key"}></textarea>
										</div>
									</div>
								{/if}
								<div class="config-row">
									<button class="config-mode-btn {showAdvancedConfig ? 'active' : ''}" on:click={() => showAdvancedConfig = !showAdvancedConfig}>
										⚙️ Advanced
									</button>
								</div>
								{#if showAdvancedConfig}
									<div class="config-row">
										<div class="config-field">
											<label class="config-label">🖼️ Crawl Iframes</label>
											<label class="toggle-switch">
												<input type="checkbox" bind:checked={crawlIframes} />
												<span class="toggle-slider"></span>
											</label>
										</div>
										<div class="config-field">
											<label class="config-label">💾 Cache Enabled</label>
											<label class="toggle-switch">
												<input type="checkbox" bind:checked={cacheEnabled} />
												<span class="toggle-slider"></span>
											</label>
										</div>
										{#if cacheEnabled}
										<div class="config-field">
											<label class="config-label">⏱️ Cache TTL (s)</label>
											<input type="number" bind:value={cacheTtlSeconds} min="60" max="86400" class="config-input" style="width: 90px;" />
										</div>
										{/if}
									</div>
									<div class="config-row">
										<div class="config-field" style="flex: 1;">
											<label class="config-label">🔗 URL Filter Patterns (comma separated, include)</label>
											<input type="text" bind:value={urlFilterPatterns} class="config-input" placeholder="/blog/,/docs/,/api/" />
										</div>
									</div>
									<div class="config-row">
										<div class="config-field" style="flex: 1;">
											<label class="config-label">🚫 URL Exclude Patterns (comma separated, exclude)</label>
											<input type="text" bind:value={urlExcludePatterns} class="config-input" placeholder="/admin/,/login/,/logout/" />
										</div>
									</div>
									<div class="config-row">
										<div class="config-field" style="flex: 1;">
											<label class="config-label">🌐 Proxy Pool (one proxy per line)</label>
											<textarea bind:value={proxyPoolProxies} class="config-input" style="height: 60px; resize: vertical; font-family: monospace; font-size: 12px;" placeholder={"http://proxy1:8080\nhttp://proxy2:3128\nsocks5://proxy3:1080"}></textarea>
										</div>
									</div>
									<div class="config-row">
										<div class="config-field">
											<label class="config-label">🔄 Proxy Rotation</label>
											<select bind:value={proxyPoolRotationMode} class="config-input" style="width: 140px;">
												<option value="round_robin">Round Robin</option>
												<option value="random">Random</option>
											</select>
										</div>
									</div>
								{/if}
							</div>
						{/if}

						{#if downloadingAll}
							<div class="download-progress-bar">
								<div class="progress-text">{$tr('webCrawler.downloading')} {downloadProgress.current}/{downloadProgress.total}...</div>
							</div>
						{/if}

						{#if downloadLog.length > 0}
							<div class="download-summary">
								<span class="dl-success">✅ {downloadLog.filter(d => d.success).length}</span>
								<span class="dl-failed">❌ {downloadLog.filter(d => !d.success).length}</span>
								<button class="dl-clear" on:click={() => downloadLog = []}>✕</button>
							</div>
							<div class="download-log-list">
								{#each downloadLog.slice(-20) as dl, i}
									<div class="dl-item {dl.success ? 'dl-item-success' : 'dl-item-fail'}">
										<span class="dl-icon">{dl.success ? '✅' : '❌'}</span>
										<span class="dl-url" title={dl.url}>{dl.url.split('/').pop() || dl.url}</span>
										{#if dl.success}
											<span class="dl-size">{dl.file_size > 1024 * 1024 ? (dl.file_size / 1024 / 1024).toFixed(1) + 'MB' : dl.file_size > 1024 ? (dl.file_size / 1024).toFixed(1) + 'KB' : dl.file_size + 'B'}</span>
										{:else}
											<span class="dl-error" title={dl.error}>{dl.error || 'Unknown error'}</span>
										{/if}
									</div>
								{/each}
								{#if downloadLog.length > 20}
									<div class="dl-more">...and {downloadLog.length - 20} more</div>
								{/if}
							</div>
						{/if}

						<div class="summary-bar">{result.summary}</div>

						<div class="result-tabs">
							<button class="result-tab {activeResultTab === 'overview' ? 'active' : ''}" on:click={() => activeResultTab = 'overview'}>
								📊 {$tr('webCrawler.tabOverview')}
							</button>
							<button class="result-tab {activeResultTab === 'links' ? 'active' : ''}" on:click={() => activeResultTab = 'links'}>
								🔗 {$tr('webCrawler.tabLinks')} ({result.links.length})
							</button>
							<button class="result-tab {activeResultTab === 'resources' ? 'active' : ''}" on:click={() => activeResultTab = 'resources'}>
								📦 {$tr('webCrawler.tabResources')} ({getTotalResources()})
							</button>
							<button class="result-tab {activeResultTab === 'api' ? 'active' : ''}" on:click={() => activeResultTab = 'api'}>
								🔌 API ({result.api_endpoints.length})
							</button>
							<button class="result-tab {activeResultTab === 'dirs' ? 'active' : ''}" on:click={() => activeResultTab = 'dirs'}>
								📁 {$tr('webCrawler.tabDirs')} ({result.directory_entries.length})
							</button>
							<button class="result-tab {activeResultTab === 'tech' ? 'active' : ''}" on:click={() => activeResultTab = 'tech'}>
								🔧 {$tr('webCrawler.tabTech')} ({result.technology_details ? result.technology_details.length : result.technologies.length})
							</button>
							<button class="result-tab {activeResultTab === 'meta' ? 'active' : ''}" on:click={() => activeResultTab = 'meta'}>
								🏷️ {$tr('webCrawler.tabMeta')}
							</button>
							<button class="result-tab {activeResultTab === 'security' ? 'active' : ''}" on:click={() => activeResultTab = 'security'}>
								🛡️ Security
							</button>
							{#if result.markdown_content}
							<button class="result-tab {activeResultTab === 'markdown' ? 'active' : ''}" on:click={() => activeResultTab = 'markdown'}>
								📝 Markdown
							</button>
							{/if}
							{#if result.subdomains && result.subdomains.length > 0}
							<button class="result-tab {activeResultTab === 'subdomains' ? 'active' : ''}" on:click={() => activeResultTab = 'subdomains'}>
								🌐 Subdomains ({result.subdomains.length})
							</button>
							{/if}
						</div>

						{#if activeResultTab === 'overview'}
							<div class="overview-grid">
								<div class="overview-stat">
									<span class="stat-label">{$tr('webCrawler.pagesCrawled')}</span>
									<span class="stat-value">{result.pages_crawled}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📧 {$tr('webCrawler.emailsFound')}</span>
									<span class="stat-value" style="color: {result.emails.length > 0 ? '#3b82f6' : '#64748b'}">{result.emails.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📜 JS</span>
									<span class="stat-value" style="color: {result.js_files.length > 0 ? '#f59e0b' : '#64748b'}">{result.js_files.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🖼️ {$tr('webCrawler.imagesFound')}</span>
									<span class="stat-value" style="color: {result.images.length > 0 ? '#22c55e' : '#64748b'}">{result.images.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🎨 CSS</span>
									<span class="stat-value" style="color: {result.css_files.length > 0 ? '#a855f7' : '#64748b'}">{result.css_files.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🎬 {$tr('webCrawler.videosFound')}</span>
									<span class="stat-value" style="color: {result.videos.length > 0 ? '#ef4444' : '#64748b'}">{result.videos.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📄 {$tr('webCrawler.docsFound')}</span>
									<span class="stat-value" style="color: {result.documents.length > 0 ? '#06b6d4' : '#64748b'}">{result.documents.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">📁 {$tr('webCrawler.dirsFound')}</span>
									<span class="stat-value" style="color: {result.directory_entries.length > 0 ? '#f59e0b' : '#64748b'}">{result.directory_entries.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">🔌 API</span>
									<span class="stat-value" style="color: {result.api_endpoints.length > 0 ? '#ef4444' : '#64748b'}">{result.api_endpoints.length}</span>
								</div>
								<div class="overview-stat">
									<span class="stat-label">💬 {$tr('webCrawler.commentsFound')}</span>
									<span class="stat-value" style="color: {result.comments.length > 0 ? '#94a3b8' : '#64748b'}">{result.comments.length}</span>
								</div>
							</div>

							{#if result.technology_details && result.technology_details.length > 0}
								<h3 class="subsection-title">🔧 {$tr('webCrawler.detectedTech')}</h3>
								<div class="tech-grid">
									{#each result.technology_details.slice(0, 12) as tech}
										<div class="tech-chip">
											<span class="tech-icon">{tech.icon || '🔧'}</span>
											<span class="tech-name">{tech.name}</span>
											{#if tech.version}
												<span class="tech-version-mini">v{tech.version}</span>
											{/if}
										</div>
									{/each}
									{#if result.technology_details.length > 12}
										<div class="tech-chip more" on:click={() => activeResultTab = 'tech'}>
											+{result.technology_details.length - 12}
										</div>
									{/if}
								</div>
							{:else if result.technologies && result.technologies.length > 0}
								<h3 class="subsection-title">🔧 {$tr('webCrawler.detectedTech')}</h3>
								<div class="tech-grid">
									{#each result.technologies.slice(0, 12) as tech}
										<div class="tech-chip">
											<span class="tech-icon">{getTechIcon(tech)}</span>
											<span class="tech-name">{tech}</span>
										</div>
									{/each}
									{#if result.technologies.length > 12}
										<div class="tech-chip more" on:click={() => activeResultTab = 'tech'}>
											+{result.technologies.length - 12}
										</div>
									{/if}
								</div>
							{/if}

							{#if result.emails.length > 0}
								<h3 class="subsection-title">📧 {$tr('webCrawler.emailList')}</h3>
								<div class="email-list">
									{#each result.emails.slice(0, 5) as email}
										<div class="email-item">📧 {email}</div>
									{/each}
									{#if result.emails.length > 5}
										<div class="more-link" on:click={() => activeResultTab = 'resources'}>
											{$tr('webCrawler.viewAll')} ({result.emails.length}) →
										</div>
									{/if}
								</div>
							{/if}

						{:else if activeResultTab === 'links'}
							<div class="filter-bar">
								<button class="filter-btn {linkFilter === 'all' ? 'active' : ''}" on:click={() => linkFilter = 'all'}>
									{$tr('webCrawler.allLinks')} ({result.links.length})
								</button>
								<button class="filter-btn {linkFilter === 'success' ? 'active' : ''}" on:click={() => linkFilter = 'success'}>
									✅ 2xx ({result.links.filter(l => l.status_code >= 200 && l.status_code < 300).length})
								</button>
								<button class="filter-btn {linkFilter === 'redirect' ? 'active' : ''}" on:click={() => linkFilter = 'redirect'}>
									↪️ 3xx ({result.links.filter(l => l.status_code >= 300 && l.status_code < 400).length})
								</button>
								<button class="filter-btn {linkFilter === 'error' ? 'active' : ''}" on:click={() => linkFilter = 'error'}>
									❌ 4xx+ ({result.links.filter(l => l.status_code >= 400).length})
								</button>
							</div>

							<div class="search-bar">
								<input type="text" bind:value={searchQuery} placeholder="{$tr('webCrawler.searchLinks')}" class="search-input" />
							</div>

							{#if getFilteredLinks().length > 0}
								<div class="links-table-wrapper">
									<table class="data-table">
										<thead>
											<tr>
												<th>{$tr('webCrawler.colStatus')}</th>
												<th>{$tr('webCrawler.colUrl')}</th>
												<th>{$tr('webCrawler.colTitle')}</th>
												<th>{$tr('webCrawler.colDepth')}</th>
												<th>{$tr('webCrawler.colTime')}</th>
											</tr>
										</thead>
										<tbody>
											{#each getFilteredLinks().slice(0, 100) as link}
												<tr>
													<td>
														<span class="status-badge" style="color: {getStatusColor(link.status_code)}; border-color: {getStatusColor(link.status_code)}40; background: {getStatusColor(link.status_code)}15">
															{link.status_code}
														</span>
													</td>
													<td class="mono url-cell">
														<a href={link.url} target="_blank" class="link-url">{link.url}</a>
													</td>
													<td class="title-cell">{link.title || '-'}</td>
													<td>
														<span class="depth-badge">D{link.depth}</span>
													</td>
													<td class="mono">{link.response_time_ms ? link.response_time_ms + 'ms' : '-'}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
								{#if getFilteredLinks().length > 100}
									<div class="table-footer">{$tr('webCrawler.showingFirst')} 100 / {getFilteredLinks().length}</div>
								{/if}
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔗</div>
									<p>{$tr('webCrawler.noLinksFound')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'resources'}
							<div class="resource-toolbar">
								<button class="btn-dl-type" on:click={() => downloadByType('js')} disabled={downloadingAll || result.js_files.length === 0}>
									⬇️ JS ({result.js_files.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('images')} disabled={downloadingAll || result.images.length === 0}>
									⬇️ 🖼️ ({result.images.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('css')} disabled={downloadingAll || result.css_files.length === 0}>
									⬇️ CSS ({result.css_files.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('videos')} disabled={downloadingAll || result.videos.length === 0}>
									⬇️ 🎬 ({result.videos.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('docs')} disabled={downloadingAll || result.documents.length === 0}>
									⬇️ 📄 ({result.documents.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('fonts')} disabled={downloadingAll || result.fonts.length === 0}>
									⬇️ 🔤 ({result.fonts.length})
								</button>
								<button class="btn-dl-type" on:click={() => downloadByType('audio')} disabled={downloadingAll || result.audio_files.length === 0}>
									⬇️ 🎵 ({result.audio_files.length})
								</button>
							</div>

							<div class="resource-section">
								{#if result.videos.length > 0}
									<h3 class="subsection-title">🎬 {$tr('webCrawler.videosFound')} ({result.videos.length})
										<button class="btn-dl-section" on:click={() => downloadByType('videos')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.videos as v}
											<div class="resource-item">
												<span class="resource-icon">{getResourceTypeIcon(v.resource_type)}</span>
												<a href={v.url} target="_blank" class="resource-url">{v.url}</a>
												<span class="resource-type-badge">{v.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(v.url)} disabled={isDownloading(v.url) || downloadingAll}>
													{#if isDownloading(v.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.audio_files.length > 0}
									<h3 class="subsection-title">🎵 {$tr('webCrawler.audioFound')} ({result.audio_files.length})
										<button class="btn-dl-section" on:click={() => downloadByType('audio')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.audio_files as audio}
											<div class="resource-item">
												<span class="resource-icon">🎵</span>
												<a href={audio.url} target="_blank" class="resource-url">{audio.url}</a>
												<span class="resource-type-badge">{audio.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(audio.url)} disabled={isDownloading(audio.url) || downloadingAll}>
													{#if isDownloading(audio.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.js_files.length > 0}
									<h3 class="subsection-title">📜 JavaScript ({result.js_files.length})
										<button class="btn-dl-section" on:click={() => downloadByType('js')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.js_files as js}
											<div class="resource-item">
												<span class="resource-icon">📜</span>
												<a href={js.url} target="_blank" class="resource-url">{js.url}</a>
												<span class="resource-type-badge">{js.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(js.url)} disabled={isDownloading(js.url) || downloadingAll}>
													{#if isDownloading(js.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.images.length > 0}
									<h3 class="subsection-title">🖼️ {$tr('webCrawler.imagesFound')} ({result.images.length})
										<button class="btn-dl-section" on:click={() => downloadByType('images')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.images as img}
											<div class="resource-item">
												<span class="resource-icon">{getResourceTypeIcon(img.resource_type)}</span>
												<a href={img.url} target="_blank" class="resource-url">{img.url}</a>
												<span class="resource-type-badge">{img.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(img.url)} disabled={isDownloading(img.url) || downloadingAll}>
													{#if isDownloading(img.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.css_files.length > 0}
									<h3 class="subsection-title">🎨 CSS ({result.css_files.length})
										<button class="btn-dl-section" on:click={() => downloadByType('css')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.css_files as css}
											<div class="resource-item">
												<span class="resource-icon">🎨</span>
												<a href={css.url} target="_blank" class="resource-url">{css.url}</a>
												<span class="resource-type-badge">{css.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(css.url)} disabled={isDownloading(css.url) || downloadingAll}>
													{#if isDownloading(css.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.fonts.length > 0}
									<h3 class="subsection-title">🔤 {$tr('webCrawler.targetFonts')} ({result.fonts.length})
										<button class="btn-dl-section" on:click={() => downloadByType('fonts')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.fonts as font}
											<div class="resource-item">
												<span class="resource-icon">🔤</span>
												<a href={font.url} target="_blank" class="resource-url">{font.url}</a>
												<span class="resource-type-badge">{font.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(font.url)} disabled={isDownloading(font.url) || downloadingAll}>
													{#if isDownloading(font.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.documents.length > 0}
									<h3 class="subsection-title">📄 {$tr('webCrawler.docsFound')} ({result.documents.length})
										<button class="btn-dl-section" on:click={() => downloadByType('docs')} disabled={downloadingAll}>⬇️</button>
									</h3>
									<div class="resource-list">
										{#each result.documents as doc}
											<div class="resource-item">
												<span class="resource-icon">{getResourceTypeIcon(doc.resource_type)}</span>
												<a href={doc.url} target="_blank" class="resource-url">{doc.url}</a>
												<span class="resource-type-badge">{doc.resource_type}</span>
												<button class="btn-dl-single" on:click={() => downloadSingle(doc.url)} disabled={isDownloading(doc.url) || downloadingAll}>
													{#if isDownloading(doc.url)}<span class="spinner-xs"></span>{:else}⬇️{/if}
												</button>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.emails.length > 0}
									<h3 class="subsection-title">📧 {$tr('webCrawler.emailList')} ({result.emails.length})</h3>
									<div class="resource-list">
										{#each result.emails as email}
											<div class="resource-item">
												<span class="resource-icon">📧</span>
												<span class="resource-url">{email}</span>
											</div>
										{/each}
									</div>
								{/if}

								{#if result.comments.length > 0}
									<h3 class="subsection-title">💬 {$tr('webCrawler.commentsFound')} ({result.comments.length})</h3>
									<div class="resource-list">
										{#each result.comments as c}
											<div class="resource-item comment-item">
												<span class="resource-icon">💬</span>
												<span class="comment-text">{c}</span>
											</div>
										{/each}
									</div>
								{/if}

								{#if getTotalResources() === 0 && result.emails.length === 0 && result.comments.length === 0}
									<div class="empty-state">
										<div class="empty-icon">📦</div>
										<p>{$tr('webCrawler.noResourcesFound')}</p>
									</div>
								{/if}
							</div>

						{:else if activeResultTab === 'api'}
							{#if result.api_endpoints.length > 0}
								<div class="api-list">
									{#each result.api_endpoints as api}
										<div class="api-item">
											<span class="method-badge" style="background: {getMethodColor(api.method)}20; color: {getMethodColor(api.method)}; border: 1px solid {getMethodColor(api.method)}40">
												{api.method}
											</span>
											<a href={api.url} target="_blank" class="api-url">{api.url}</a>
											<span class="api-source">{api.source}</span>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔌</div>
									<p>{$tr('webCrawler.noApiFound')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'dirs'}
							{#if result.directory_entries.length > 0}
								<div class="dir-summary">
									<span class="dir-stat">📁 {$tr('webCrawler.dirsFound')}: {result.directory_entries.filter(d => d.is_directory).length}</span>
									<span class="dir-stat">📄 {$tr('webCrawler.filesFound')}: {result.directory_entries.filter(d => !d.is_directory).length}</span>
								</div>
								<div class="dir-tree">
									{#each result.directory_entries as entry}
										<div class="dir-entry {entry.is_directory ? 'is-dir' : 'is-file'}">
											<span class="dir-icon">{entry.is_directory ? '📁' : '📄'}</span>
											<a href={entry.full_url} target="_blank" class="dir-path">{entry.path}</a>
											<span class="status-badge" style="color: {getStatusColor(entry.status_code)}; border-color: {getStatusColor(entry.status_code)}40; background: {getStatusColor(entry.status_code)}15">
												{entry.status_code}
											</span>
											{#if entry.content_length}
												<span class="dir-size">{formatFileSize(entry.content_length)}</span>
											{/if}
											{#if entry.content_type}
												<span class="dir-type">{entry.content_type.split(';')[0]}</span>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">📁</div>
									<p>{$tr('webCrawler.noDirsFound')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'tech'}
							{#if result.technology_details && result.technology_details.length > 0}
								{@const categories = [...new Set(result.technology_details.map((t: any) => t.category))]}
								{#each categories as category}
									{@const techsInCategory = result.technology_details.filter((t: any) => t.category === category)}
									<div class="tech-category-section">
										<div class="tech-category-header">
											<span class="tech-category-name">{category}</span>
											<span class="tech-category-count">{techsInCategory.length}</span>
										</div>
										<div class="tech-detail-grid">
											{#each techsInCategory as tech}
												<div class="tech-detail-card" class:high-confidence={tech.confidence >= 0.7} class:medium-confidence={tech.confidence >= 0.4 && tech.confidence < 0.7} class:low-confidence={tech.confidence < 0.4}>
													<div class="tech-card-top">
														<span class="tech-detail-icon">{tech.icon || '🔧'}</span>
														<span class="tech-detail-name">{tech.name}</span>
														{#if tech.version}
															<span class="tech-version">v{tech.version}</span>
														{/if}
													</div>
													<div class="tech-card-bottom">
														<div class="tech-confidence-bar">
															<div class="tech-confidence-fill" style="width: {Math.round(tech.confidence * 100)}%"></div>
														</div>
														<span class="tech-confidence-text">{Math.round(tech.confidence * 100)}%</span>
													</div>
													{#if tech.evidence && tech.evidence.length > 0}
														<div class="tech-evidence-list">
															{#each tech.evidence.slice(0, 2) as ev}
																<span class="tech-evidence-item">{ev}</span>
															{/each}
														</div>
													{/if}
												</div>
											{/each}
										</div>
									</div>
								{/each}
							{:else if result.technologies && result.technologies.length > 0}
								<div class="tech-detail-grid">
									{#each result.technologies as tech}
										<div class="tech-detail-card">
											<span class="tech-detail-icon">{getTechIcon(tech)}</span>
											<span class="tech-detail-name">{tech}</span>
										</div>
									{/each}
								</div>
							{:else}
								<div class="empty-state">
									<div class="empty-icon">🔧</div>
									<p>{$tr('webCrawler.noTechFound')}</p>
								</div>
							{/if}

						{:else if activeResultTab === 'meta'}
							<div class="detail-section">
								{#if result.metadata.title}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaTitle')}</span>
										<span class="detail-value">{result.metadata.title}</span>
									</div>
								{/if}
								{#if result.metadata.description}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaDesc')}</span>
										<span class="detail-value">{result.metadata.description}</span>
									</div>
								{/if}
								{#if result.metadata.keywords}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaKeywords')}</span>
										<span class="detail-value">{result.metadata.keywords}</span>
									</div>
								{/if}
								{#if result.metadata.author}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaAuthor')}</span>
										<span class="detail-value">{result.metadata.author}</span>
									</div>
								{/if}
								{#if result.metadata.generator}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaGenerator')}</span>
										<span class="detail-value">{result.metadata.generator}</span>
									</div>
								{/if}
								{#if result.metadata.canonical}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaCanonical')}</span>
										<span class="detail-value mono">{result.metadata.canonical}</span>
									</div>
								{/if}
								{#if result.metadata.robots}
									<div class="detail-row">
										<span class="detail-label">{$tr('webCrawler.metaRobots')}</span>
										<span class="detail-value">{result.metadata.robots}</span>
									</div>
								{/if}
								{#if result.metadata.og_title}
									<div class="detail-row">
										<span class="detail-label">OG Title</span>
										<span class="detail-value">{result.metadata.og_title}</span>
									</div>
								{/if}
								{#if result.metadata.og_description}
									<div class="detail-row">
										<span class="detail-label">OG Description</span>
										<span class="detail-value">{result.metadata.og_description}</span>
									</div>
								{/if}
								{#if result.metadata.og_image}
									<div class="detail-row">
										<span class="detail-label">OG Image</span>
										<span class="detail-value mono">{result.metadata.og_image}</span>
									</div>
								{/if}
								{#if result.metadata.og_video}
									<div class="detail-row">
										<span class="detail-label">OG Video</span>
										<span class="detail-value mono">{result.metadata.og_video}</span>
									</div>
								{/if}
								{#if result.metadata.og_audio}
									<div class="detail-row">
										<span class="detail-label">OG Audio</span>
										<span class="detail-value mono">{result.metadata.og_audio}</span>
									</div>
								{/if}
								{#if result.metadata.og_type}
									<div class="detail-row">
										<span class="detail-label">OG Type</span>
										<span class="detail-value">{result.metadata.og_type}</span>
									</div>
								{/if}
								{#if result.metadata.og_site_name}
									<div class="detail-row">
										<span class="detail-label">OG Site Name</span>
										<span class="detail-value">{result.metadata.og_site_name}</span>
									</div>
								{/if}
								{#if result.metadata.twitter_card}
									<div class="detail-row">
										<span class="detail-label">Twitter Card</span>
										<span class="detail-value">{result.metadata.twitter_card}</span>
									</div>
								{/if}
								{#if result.metadata.twitter_title}
									<div class="detail-row">
										<span class="detail-label">Twitter Title</span>
										<span class="detail-value">{result.metadata.twitter_title}</span>
									</div>
								{/if}
								{#if result.metadata.twitter_description}
									<div class="detail-row">
										<span class="detail-label">Twitter Description</span>
										<span class="detail-value">{result.metadata.twitter_description}</span>
									</div>
								{/if}
								{#if result.metadata.twitter_image}
									<div class="detail-row">
										<span class="detail-label">Twitter Image</span>
										<span class="detail-value mono">{result.metadata.twitter_image}</span>
									</div>
								{/if}
								{#if !result.metadata.title && !result.metadata.description && !result.metadata.keywords}
									<div class="empty-state">
										<div class="empty-icon">🏷️</div>
										<p>{$tr('webCrawler.noMetaFound')}</p>
									</div>
								{/if}
							</div>
						{:else if activeResultTab === 'security'}
							<div class="detail-section">
								<div class="security-score-card">
									<div class="score-circle" style="border-color: {getSecurityScoreColor(result.security_info.security_score)}">
										<span class="score-number" style="color: {getSecurityScoreColor(result.security_info.security_score)}">{result.security_info.security_score}</span>
										<span class="score-max">/100</span>
									</div>
									<span class="score-title">Security Score</span>
								</div>
								<div class="security-checks">
									<div class="security-check {result.security_info.has_https ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_https ? '✅' : '❌'}</span>
										<span class="check-label">HTTPS</span>
									</div>
									<div class="security-check {result.security_info.has_hsts ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_hsts ? '✅' : '❌'}</span>
										<span class="check-label">HSTS</span>
									</div>
									<div class="security-check {result.security_info.has_csp ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_csp ? '✅' : '❌'}</span>
										<span class="check-label">CSP</span>
									</div>
									<div class="security-check {result.security_info.has_x_frame_options ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_x_frame_options ? '✅' : '❌'}</span>
										<span class="check-label">X-Frame-Options</span>
									</div>
									<div class="security-check {result.security_info.has_x_content_type_options ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_x_content_type_options ? '✅' : '❌'}</span>
										<span class="check-label">X-Content-Type-Options</span>
									</div>
									<div class="security-check {result.security_info.has_x_xss_protection ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_x_xss_protection ? '✅' : '❌'}</span>
										<span class="check-label">X-XSS-Protection</span>
									</div>
									<div class="security-check {result.security_info.has_referrer_policy ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_referrer_policy ? '✅' : '❌'}</span>
										<span class="check-label">Referrer-Policy</span>
									</div>
									<div class="security-check {result.security_info.has_permissions_policy ? 'pass' : 'fail'}">
										<span class="check-icon">{result.security_info.has_permissions_policy ? '✅' : '❌'}</span>
										<span class="check-label">Permissions-Policy</span>
									</div>
								</div>
								{#if result.security_info.csp_directives}
									<div class="detail-row">
										<span class="detail-label">CSP Directives</span>
										<span class="detail-value mono" style="font-size: 11px; word-break: break-all;">{result.security_info.csp_directives}</span>
									</div>
								{/if}
								{#if result.security_info.server_header}
									<div class="detail-row">
										<span class="detail-label">Server</span>
										<span class="detail-value mono">{result.security_info.server_header}</span>
									</div>
								{/if}
								{#if result.security_info.powered_by_header}
									<div class="detail-row">
										<span class="detail-label">X-Powered-By</span>
										<span class="detail-value mono">{result.security_info.powered_by_header}</span>
									</div>
								{/if}
								{#if result.antibot_detection && result.antibot_detection.detected}
									<div class="antibot-warning">
										<div class="warning-header">
											<span class="warning-icon">🚨</span>
											<span class="warning-title">Anti-bot Protection Detected</span>
										</div>
										{#if result.antibot_detection.protection_type}
											<div class="detail-row">
												<span class="detail-label">Type</span>
												<span class="detail-value">{result.antibot_detection.protection_type}</span>
											</div>
										{/if}
										<div class="detail-row">
											<span class="detail-label">Confidence</span>
											<span class="detail-value">{(result.antibot_detection.confidence * 100).toFixed(0)}%</span>
										</div>
										{#if result.antibot_detection.details.length > 0}
											<div class="antibot-details">
												{#each result.antibot_detection.details as detail}
													<div class="antibot-detail-item">• {detail}</div>
												{/each}
											</div>
										{/if}
									</div>
								{:else if result.antibot_detection}
									<div class="antibot-safe">
										<span class="safe-icon">✅</span>
										<span>No anti-bot protection detected</span>
									</div>
								{/if}

								{#if result.paywall_detection && result.paywall_detection.detected}
									<div class="antibot-warning" style="border-color: #f59e0b; background: rgba(245, 158, 11, 0.08);">
										<div class="warning-header">
											<span class="warning-icon">🔒</span>
											<span class="warning-title">Paywall / Download Limit Detected</span>
										</div>
										{#if result.paywall_detection.paywall_type}
											<div class="detail-row">
												<span class="detail-label">Type</span>
												<span class="detail-value">{result.paywall_detection.paywall_type}</span>
											</div>
										{/if}
										<div class="detail-row">
											<span class="detail-label">Confidence</span>
											<span class="detail-value">{(result.paywall_detection.confidence * 100).toFixed(0)}%</span>
										</div>
										{#if result.paywall_detection.details.length > 0}
											<div class="antibot-details">
												{#each result.paywall_detection.details as detail}
													<div class="antibot-detail-item">• {detail}</div>
												{/each}
											</div>
										{/if}
										<div class="detail-row" style="margin-top: 8px;">
											<span class="detail-label" style="color: #f59e0b;">💡 Tip</span>
											<span class="detail-value" style="font-size: 12px;">Use Cookie/Auth settings to bypass login walls, or set priority order to maximize value within download limits</span>
										</div>
									</div>
								{/if}

								{#if result.popup_detection && result.popup_detection.detected}
									<div class="antibot-warning" style="border-color: #8b5cf6; background: rgba(139, 92, 246, 0.08);">
										<div class="warning-header">
											<span class="warning-icon">🔔</span>
											<span class="warning-title">Popup / Overlay Detected</span>
										</div>
										{#if result.popup_detection.popup_types.length > 0}
											<div class="detail-row">
												<span class="detail-label">Types</span>
												<span class="detail-value">{result.popup_detection.popup_types.join(', ')}</span>
											</div>
										{/if}
										<div class="detail-row">
											<span class="detail-label">Confidence</span>
											<span class="detail-value">{(result.popup_detection.confidence * 100).toFixed(0)}%</span>
										</div>
										{#if result.popup_detection.details.length > 0}
											<div class="antibot-details">
												{#each result.popup_detection.details as detail}
													<div class="antibot-detail-item">• {detail}</div>
												{/each}
											</div>
										{/if}
									</div>
								{/if}

								{#if result.ssl_cert_info}
									<h3 class="subsection-title" style="margin-top: 16px;">🔒 SSL Certificate</h3>
									<div class="detail-row">
										<span class="detail-label">Subject</span>
										<span class="detail-value mono" style="font-size: 11px;">{result.ssl_cert_info.subject || 'N/A'}</span>
									</div>
									<div class="detail-row">
										<span class="detail-label">Issuer</span>
										<span class="detail-value mono" style="font-size: 11px;">{result.ssl_cert_info.issuer || 'N/A'}</span>
									</div>
									{#if result.ssl_cert_info.not_after}
									<div class="detail-row">
										<span class="detail-label">Expires</span>
										<span class="detail-value mono" style="color: {result.ssl_cert_info.is_expired ? '#ef4444' : result.ssl_cert_info.days_remaining !== null && result.ssl_cert_info.days_remaining < 30 ? '#f59e0b' : '#22c55e'}">{result.ssl_cert_info.not_after}</span>
										{#if result.ssl_cert_info.days_remaining !== null}
											<span style="font-size: 11px; color: {result.ssl_cert_info.days_remaining < 30 ? '#f59e0b' : '#64748b'}; margin-left: 8px;">({result.ssl_cert_info.is_expired ? 'EXPIRED' : result.ssl_cert_info.days_remaining + ' days remaining'})</span>
										{/if}
									</div>
									{/if}
									{#if result.ssl_cert_info.fingerprint_sha256}
									<div class="detail-row">
										<span class="detail-label">SHA256</span>
										<span class="detail-value mono" style="font-size: 10px; word-break: break-all;">{result.ssl_cert_info.fingerprint_sha256}</span>
									</div>
									{/if}
									{#if result.ssl_cert_info.subject_alt_names.length > 0}
									<div class="detail-row">
										<span class="detail-label">SANs</span>
										<span class="detail-value mono" style="font-size: 11px;">{result.ssl_cert_info.subject_alt_names.join(', ')}</span>
									</div>
									{/if}
								{/if}
							</div>
						{:else if activeResultTab === 'markdown'}
							<div class="detail-section">
								<div style="display: flex; justify-content: flex-end; margin-bottom: 8px;">
									<button class="action-btn" on:click={() => {
										if (result?.markdown_content) {
											navigator.clipboard.writeText(result.markdown_content);
										}
									}}>📋 Copy</button>
								</div>
								<pre class="markdown-content" style="white-space: pre-wrap; word-break: break-word; font-size: 13px; line-height: 1.6; max-height: 600px; overflow-y: auto; padding: 16px; background: #1e293b; border-radius: 8px; color: #e2e8f0;">{result.markdown_content}</pre>
							</div>
						{:else if activeResultTab === 'subdomains'}
							<div class="detail-section">
								{#if result.subdomains && result.subdomains.length > 0}
									<div class="subdomain-list">
										{#each result.subdomains as sub}
											<div class="subdomain-item">
												<span class="subdomain-icon">🌐</span>
												<span class="subdomain-name mono">{sub}</span>
											</div>
										{/each}
									</div>
								{:else}
									<div class="empty-state">
										<div class="empty-icon">🌐</div>
										<p>No subdomains found</p>
									</div>
								{/if}
							</div>
						{/if}
					{:else}
						<div class="empty-state">
							<div class="empty-icon">🕷️</div>
							<p>{$tr('webCrawler.noResults')}</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	{:else if activeMainTab === 'history'}
		<div class="section-card">
			<ToolHistory toolType="web_crawler" toolName={$tr('webCrawler.title')} bind:this={historyComponent} />
		</div>
	{:else if activeMainTab === 'help'}
		<div class="section-card">
			<ToolHelp toolType="web_crawler" />
		</div>
	{/if}
</div>

<style>
	.nd-page {
		padding: 1.5rem;
		max-width: 1200px;
		margin: 0 auto;
		min-height: 100vh;
	}

	.page-header {
		margin-bottom: 1.5rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid rgba(168, 85, 247, 0.15);
	}

	.back-link {
		color: #94a3b8;
		text-decoration: none;
		font-size: 0.8rem;
		transition: color 0.2s;
	}

	.back-link:hover { color: #a855f7; }

	.page-title {
		font-size: 1.5rem;
		font-weight: 700;
		margin: 0.5rem 0 0.25rem;
		color: #f1f5f9;
	}

	.page-subtitle {
		color: #94a3b8;
		font-size: 0.875rem;
		margin: 0;
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1.25rem;
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 0.25rem;
	}

	.tab-btn {
		flex: 1;
		padding: 0.6rem 1rem;
		border: none;
		border-radius: 0.5rem;
		background: transparent;
		cursor: pointer;
		font-size: 0.85rem;
		color: #94a3b8;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
	}

	.tab-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		box-shadow: 0 2px 8px rgba(168, 85, 247, 0.3);
	}

	.tab-btn:hover:not(.active) { background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }

	.tab-icon { font-size: 0.9rem; }

	.content-grid {
		display: grid;
		grid-template-columns: 340px 1fr;
		gap: 1.25rem;
	}

	.section-card {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.15);
		border-radius: 0.75rem;
		padding: 1.25rem;
	}

	.section-title {
		font-size: 1rem;
		font-weight: 600;
		color: #f1f5f9;
		margin: 0 0 1rem;
	}

	.section-desc {
		font-size: 0.8rem;
		color: #94a3b8;
		margin: 0.25rem 0 0;
	}

	.form-group { margin-bottom: 0.75rem; }

	.form-label {
		display: block;
		font-size: 0.75rem;
		color: #94a3b8;
		margin-bottom: 0.3rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.form-input {
		width: 100%;
		padding: 0.55rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8);
		color: #f1f5f9;
		font-size: 0.85rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
	}

	.form-input:focus {
		outline: none;
		border-color: #a855f7;
		box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.15);
	}

	.form-input::placeholder { color: #475569; }

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.mode-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.35rem;
	}

	.mode-btn {
		padding: 0.4rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
		text-align: center;
	}

	.mode-btn.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
		box-shadow: 0 2px 6px rgba(168, 85, 247, 0.3);
	}

	.mode-btn:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.mode-name { font-size: 0.75rem; }

	.target-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.35rem;
	}

	.target-chip {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.35rem 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem;
		background: rgba(15, 23, 42, 0.6);
		cursor: pointer;
		font-size: 0.75rem;
		color: #94a3b8;
		transition: all 0.2s;
	}

	.target-chip.active {
		border-color: rgba(168, 85, 247, 0.4);
		background: rgba(168, 85, 247, 0.1);
		color: #c4b5fd;
	}

	.target-chip input[type="checkbox"] {
		accent-color: #a855f7;
		width: 0.8rem;
		height: 0.8rem;
	}

	.target-chip:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
	}

	.button-group {
		display: flex;
		gap: 0.5rem;
		margin-top: 1rem;
	}

	.btn-primary {
		flex: 1;
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		font-weight: 600;
		padding: 0.65rem 1.25rem;
		border: none;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		font-size: 0.9rem;
	}

	.btn-primary:hover:not(:disabled) {
		box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4);
		transform: translateY(-1px);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		transform: none;
		box-shadow: none;
	}

	.btn-secondary {
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		padding: 0.65rem 1rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
	}

	.btn-secondary:hover:not(:disabled) {
		background: rgba(148, 163, 184, 0.2);
		color: #e2e8f0;
	}

	.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-accent {
		background: linear-gradient(135deg, #f59e0b, #d97706);
		color: #fff;
		padding: 0.65rem 1.2rem;
		border: none;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.2s;
		font-size: 0.9rem;
		font-weight: 600;
		box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3);
	}

	.btn-accent:hover:not(:disabled) {
		background: linear-gradient(135deg, #d97706, #b45309);
		transform: translateY(-1px);
		box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
	}

	.btn-accent:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

	.spinner {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.2);
		border-radius: 0.5rem;
	}

	.error-icon { font-size: 1.25rem; }

	.error-text { color: #fca5a5; font-size: 0.85rem; }

	.result-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.resource-score-badge {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(168, 85, 247, 0.1);
	}

	.score-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #a855f7;
		line-height: 1;
	}

	.score-label {
		font-size: 0.65rem;
		color: #a855f7;
		opacity: 0.8;
		margin-top: 0.2rem;
	}

	.summary-bar {
		font-size: 0.8rem;
		color: #94a3b8;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		margin-bottom: 1rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.result-tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1rem;
		flex-wrap: wrap;
	}

	.result-tab {
		padding: 0.4rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.result-tab.active {
		background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%);
		color: white;
		border-color: transparent;
		font-weight: 600;
	}

	.result-tab:hover:not(.active) {
		border-color: rgba(168, 85, 247, 0.3);
		color: #c4b5fd;
	}

	.overview-grid {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.overview-stat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.08);
		border-radius: 0.5rem;
	}

	.stat-label {
		font-size: 0.7rem;
		color: #94a3b8;
		margin-bottom: 0.25rem;
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 700;
		color: #f1f5f9;
	}

	.subsection-title {
		font-size: 0.9rem;
		font-weight: 600;
		color: #e2e8f0;
		margin: 1rem 0 0.5rem;
	}

	.tech-grid {
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem;
	}

	.tech-chip {
		display: flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.35rem 0.6rem;
		background: rgba(168, 85, 247, 0.1);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.4rem;
		font-size: 0.75rem;
		color: #c4b5fd;
	}

	.tech-chip.more {
		cursor: pointer;
		color: #a855f7;
		border-color: rgba(168, 85, 247, 0.4);
	}

	.tech-icon { font-size: 0.8rem; }

	.tech-name { font-size: 0.75rem; }

	.tech-version-mini {
		font-size: 0.55rem;
		padding: 0.05rem 0.25rem;
		background: rgba(34, 197, 94, 0.15);
		color: #86efac;
		border-radius: 0.2rem;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.email-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.email-item {
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.3rem;
		font-size: 0.8rem;
		color: #cbd5e1;
	}

	.more-link {
		padding: 0.4rem 0.6rem;
		color: #a855f7;
		cursor: pointer;
		font-size: 0.8rem;
		transition: color 0.2s;
	}

	.more-link:hover { color: #c4b5fd; }

	.filter-bar {
		display: flex;
		gap: 0.3rem;
		margin-bottom: 0.75rem;
		flex-wrap: wrap;
	}

	.filter-btn {
		padding: 0.35rem 0.6rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.filter-btn.active {
		background: rgba(168, 85, 247, 0.15);
		border-color: rgba(168, 85, 247, 0.4);
		color: #c4b5fd;
	}

	.filter-btn:hover:not(.active) {
		border-color: rgba(148, 163, 184, 0.3);
	}

	.search-bar { margin-bottom: 0.75rem; }

	.search-input {
		width: 100%;
		padding: 0.45rem 0.75rem;
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.6);
		color: #f1f5f9;
		font-size: 0.8rem;
		box-sizing: border-box;
	}

	.search-input:focus {
		outline: none;
		border-color: #a855f7;
	}

	.search-input::placeholder { color: #475569; }

	.links-table-wrapper {
		max-height: 500px;
		overflow-y: auto;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.data-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.8rem;
	}

	.data-table th {
		text-align: left;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.6);
		color: #94a3b8;
		font-weight: 500;
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
		position: sticky;
		top: 0;
		z-index: 1;
	}

	.data-table td {
		padding: 0.4rem 0.6rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.06);
		color: #cbd5e1;
	}

	.data-table tr:hover td { background: rgba(168, 85, 247, 0.05); }

	.status-badge {
		display: inline-block;
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 600;
		border: 1px solid;
	}

	.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.78rem; }

	.url-cell { max-width: 300px; }

	.link-url {
		color: #a855f7;
		text-decoration: none;
		font-size: 0.78rem;
		display: block;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 280px;
	}

	.link-url:hover { color: #c4b5fd; text-decoration: underline; }

	.title-cell {
		max-width: 150px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.78rem;
		color: #94a3b8;
	}

	.depth-badge {
		display: inline-block;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(148, 163, 184, 0.1);
		font-size: 0.7rem;
		color: #94a3b8;
	}

	.table-footer {
		text-align: center;
		padding: 0.5rem;
		font-size: 0.75rem;
		color: #64748b;
	}

	.resource-section { max-height: 600px; overflow-y: auto; }

	.resource-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		margin-bottom: 0.5rem;
	}

	.resource-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.3rem;
		font-size: 0.8rem;
	}

	.resource-icon { font-size: 0.85rem; flex-shrink: 0; }

	.resource-url {
		flex: 1;
		color: #a855f7;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.75rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.resource-url:hover { color: #c4b5fd; text-decoration: underline; }

	.resource-type-badge {
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		background: rgba(148, 163, 184, 0.1);
		font-size: 0.65rem;
		color: #94a3b8;
		flex-shrink: 0;
	}

	.comment-item { align-items: flex-start; }

	.comment-text {
		color: #94a3b8;
		font-style: italic;
		font-size: 0.78rem;
		line-height: 1.4;
		word-break: break-all;
	}

	.api-list {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.api-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.3rem;
	}

	.method-badge {
		padding: 0.2rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		font-weight: 700;
		flex-shrink: 0;
		min-width: 50px;
		text-align: center;
	}

	.api-url {
		flex: 1;
		color: #a855f7;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.75rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.api-url:hover { color: #c4b5fd; text-decoration: underline; }

	.api-source {
		font-size: 0.65rem;
		color: #64748b;
		flex-shrink: 0;
	}

	.tech-category-section {
		margin-bottom: 1.2rem;
	}

	.tech-category-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.6rem;
		padding-bottom: 0.4rem;
		border-bottom: 1px solid rgba(148, 163, 184, 0.1);
	}

	.tech-category-name {
		font-size: 0.85rem;
		font-weight: 600;
		color: #c4b5fd;
		letter-spacing: 0.02em;
	}

	.tech-category-count {
		font-size: 0.65rem;
		padding: 0.1rem 0.4rem;
		background: rgba(168, 85, 247, 0.2);
		border-radius: 9999px;
		color: #c4b5fd;
		font-weight: 600;
	}

	.tech-detail-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 0.5rem;
	}

	.tech-detail-card {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		padding: 0.65rem 0.75rem;
		background: rgba(168, 85, 247, 0.06);
		border: 1px solid rgba(168, 85, 247, 0.12);
		border-radius: 0.5rem;
		transition: all 0.2s;
	}

	.tech-detail-card:hover {
		background: rgba(168, 85, 247, 0.12);
		border-color: rgba(168, 85, 247, 0.25);
		transform: translateY(-1px);
	}

	.tech-detail-card.high-confidence {
		border-left: 3px solid rgba(34, 197, 94, 0.6);
	}

	.tech-detail-card.medium-confidence {
		border-left: 3px solid rgba(234, 179, 8, 0.6);
	}

	.tech-detail-card.low-confidence {
		border-left: 3px solid rgba(239, 68, 68, 0.5);
	}

	.tech-card-top {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.tech-detail-icon { font-size: 1rem; }

	.tech-detail-name {
		font-size: 0.8rem;
		color: #e2e8f0;
		font-weight: 500;
		flex: 1;
	}

	.tech-version {
		font-size: 0.65rem;
		padding: 0.1rem 0.35rem;
		background: rgba(34, 197, 94, 0.15);
		color: #86efac;
		border-radius: 0.25rem;
		font-weight: 600;
		font-family: 'SF Mono', 'Fira Code', monospace;
	}

	.tech-card-bottom {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.tech-confidence-bar {
		flex: 1;
		height: 3px;
		background: rgba(148, 163, 184, 0.15);
		border-radius: 2px;
		overflow: hidden;
	}

	.tech-confidence-fill {
		height: 100%;
		border-radius: 2px;
		background: linear-gradient(90deg, rgba(168, 85, 247, 0.6), rgba(168, 85, 247, 1));
		transition: width 0.3s ease;
	}

	.tech-confidence-text {
		font-size: 0.6rem;
		color: #94a3b8;
		font-weight: 600;
		min-width: 28px;
		text-align: right;
	}

	.tech-evidence-list {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}

	.tech-evidence-item {
		font-size: 0.6rem;
		color: #64748b;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.detail-section {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.detail-row {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.06);
	}

	.detail-label {
		font-size: 0.75rem;
		color: #94a3b8;
		font-weight: 500;
		flex-shrink: 0;
		margin-right: 1rem;
	}

	.detail-value {
		font-size: 0.8rem;
		color: #e2e8f0;
		text-align: right;
		word-break: break-word;
	}

	.empty-state {
		text-align: center;
		padding: 2.5rem 1rem;
		color: #94a3b8;
	}

	.empty-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }

	.empty-state p { font-size: 0.85rem; margin: 0; }

	.header-actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-shrink: 0;
	}

	.btn-config-toggle {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.3);
		background: rgba(148, 163, 184, 0.1);
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.85rem;
		transition: all 0.2s;
	}

	.btn-config-toggle:hover {
		background: rgba(148, 163, 184, 0.2);
		border-color: rgba(148, 163, 184, 0.5);
		color: #e2e8f0;
	}

	.btn-download-site {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.5rem 0.85rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(59, 130, 246, 0.3);
		background: rgba(59, 130, 246, 0.1);
		color: #3b82f6;
		cursor: pointer;
		font-size: 0.8rem;
		font-weight: 600;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.btn-download-site:hover:not(:disabled) {
		background: rgba(59, 130, 246, 0.2);
		border-color: rgba(59, 130, 246, 0.5);
	}

	.btn-download-site:disabled { opacity: 0.5; cursor: not-allowed; }

	.download-config-panel {
		background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(168, 85, 247, 0.2);
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
		margin-bottom: 0.75rem;
	}

	.config-row {
		display: flex;
		align-items: center;
		gap: 1rem;
		margin-bottom: 0.5rem;
	}

	.config-row:last-child { margin-bottom: 0; }

	.config-label {
		font-size: 0.75rem;
		color: #94a3b8;
		white-space: nowrap;
		min-width: fit-content;
	}

	.config-mode-btns {
		display: flex;
		gap: 0.25rem;
	}

	.config-mode-btn {
		padding: 0.3rem 0.6rem;
		border-radius: 0.375rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		background: transparent;
		color: #94a3b8;
		cursor: pointer;
		font-size: 0.7rem;
		transition: all 0.2s;
	}

	.config-mode-btn.active {
		background: rgba(168, 85, 247, 0.2);
		border-color: rgba(168, 85, 247, 0.5);
		color: #a855f7;
	}

	.config-mode-btn:hover:not(.active) {
		background: rgba(148, 163, 184, 0.1);
		border-color: rgba(148, 163, 184, 0.3);
	}

	.config-field {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.config-input {
		width: 4.5rem;
		padding: 0.25rem 0.4rem;
		border-radius: 0.375rem;
		border: 1px solid rgba(148, 163, 184, 0.2);
		background: rgba(15, 23, 42, 0.8);
		color: #e2e8f0;
		font-size: 0.75rem;
		text-align: center;
	}

	.config-input:focus {
		outline: none;
		border-color: rgba(168, 85, 247, 0.5);
	}

	.btn-download-all {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.5rem 0.85rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.1);
		color: #22c55e;
		cursor: pointer;
		font-size: 0.8rem;
		font-weight: 600;
		transition: all 0.2s;
		white-space: nowrap;
	}

	.btn-download-all:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.2);
		border-color: rgba(34, 197, 94, 0.5);
	}

	.btn-download-all:disabled { opacity: 0.5; cursor: not-allowed; }

	.spinner-sm {
		display: inline-block;
		width: 0.85rem;
		height: 0.85rem;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	.spinner-xs {
		display: inline-block;
		width: 0.7rem;
		height: 0.7rem;
		border: 1.5px solid rgba(168, 85, 247, 0.3);
		border-top-color: #a855f7;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	.download-progress-bar {
		padding: 0.5rem 0.75rem;
		background: rgba(34, 197, 94, 0.1);
		border: 1px solid rgba(34, 197, 94, 0.2);
		border-radius: 0.4rem;
		margin-bottom: 0.75rem;
	}

	.progress-text {
		font-size: 0.8rem;
		color: #22c55e;
	}

	.download-summary {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.3rem;
		margin-bottom: 0.5rem;
		font-size: 0.8rem;
	}

	.dl-success { color: #22c55e; }
	.dl-failed { color: #ef4444; }

	.dl-clear {
		margin-left: auto;
		background: none;
		border: none;
		color: #64748b;
		cursor: pointer;
		font-size: 0.75rem;
		padding: 0.1rem 0.3rem;
	}

	.dl-clear:hover { color: #94a3b8; }

	.download-log-list {
		max-height: 200px;
		overflow-y: auto;
		background: rgba(15, 23, 42, 0.3);
		border-radius: 0.3rem;
		margin-bottom: 0.5rem;
		font-size: 0.75rem;
	}

	.dl-item {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.25rem 0.5rem;
		border-bottom: 1px solid rgba(100, 116, 139, 0.1);
	}

	.dl-item-success { color: #94a3b8; }
	.dl-item-fail { color: #f87171; }

	.dl-icon { flex-shrink: 0; }

	.dl-url {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: #cbd5e1;
	}

	.dl-size {
		flex-shrink: 0;
		color: #22c55e;
		font-size: 0.7rem;
	}

	.dl-error {
		flex-shrink: 0;
		max-width: 150px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: #f87171;
		font-size: 0.7rem;
	}

	.dl-more {
		text-align: center;
		padding: 0.3rem;
		color: #64748b;
		font-size: 0.7rem;
	}

	.resource-toolbar {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		margin-bottom: 0.75rem;
	}

	.btn-dl-type {
		padding: 0.35rem 0.6rem;
		border-radius: 0.3rem;
		border: 1px solid rgba(34, 197, 94, 0.2);
		background: rgba(34, 197, 94, 0.05);
		color: #22c55e;
		cursor: pointer;
		font-size: 0.75rem;
		transition: all 0.2s;
	}

	.btn-dl-type:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.15);
		border-color: rgba(34, 197, 94, 0.4);
	}

	.btn-dl-type:disabled { opacity: 0.4; cursor: not-allowed; }

	.btn-dl-section {
		background: none;
		border: 1px solid rgba(34, 197, 94, 0.3);
		border-radius: 0.25rem;
		color: #22c55e;
		cursor: pointer;
		font-size: 0.7rem;
		padding: 0.15rem 0.35rem;
		margin-left: 0.5rem;
		transition: all 0.2s;
	}

	.btn-dl-section:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.1);
	}

	.btn-dl-section:disabled { opacity: 0.4; cursor: not-allowed; }

	.btn-dl-single {
		background: none;
		border: 1px solid rgba(34, 197, 94, 0.3);
		border-radius: 0.25rem;
		color: #22c55e;
		cursor: pointer;
		font-size: 0.75rem;
		padding: 0.15rem 0.4rem;
		flex-shrink: 0;
		transition: all 0.2s;
		line-height: 1;
	}

	.btn-dl-single:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.15);
		border-color: rgba(34, 197, 94, 0.5);
	}

	.btn-dl-single:disabled { opacity: 0.4; cursor: not-allowed; }

	.dir-summary {
		display: flex;
		gap: 1rem;
		margin-bottom: 0.75rem;
		padding: 0.5rem 0.75rem;
		background: rgba(15, 23, 42, 0.4);
		border-radius: 0.4rem;
		border: 1px solid rgba(148, 163, 184, 0.08);
	}

	.dir-stat {
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.dir-tree {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		max-height: 500px;
		overflow-y: auto;
	}

	.dir-entry {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		background: rgba(15, 23, 42, 0.4);
		border: 1px solid rgba(148, 163, 184, 0.06);
		border-radius: 0.3rem;
		font-size: 0.8rem;
	}

	.dir-entry.is-dir {
		border-left: 3px solid rgba(245, 158, 11, 0.5);
	}

	.dir-entry.is-file {
		border-left: 3px solid rgba(148, 163, 184, 0.15);
	}

	.dir-icon { font-size: 0.85rem; flex-shrink: 0; }

	.dir-path {
		flex: 1;
		color: #a855f7;
		text-decoration: none;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.75rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.dir-path:hover { color: #c4b5fd; text-decoration: underline; }

	.dir-size {
		font-size: 0.7rem;
		color: #64748b;
		flex-shrink: 0;
	}

	.dir-type {
		font-size: 0.65rem;
		color: #64748b;
		flex-shrink: 0;
		max-width: 120px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.export-select {
		padding: 0.4rem 0.6rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(168, 85, 247, 0.3);
		background: rgba(15, 23, 42, 0.8);
		color: #e2e8f0;
		font-size: 0.75rem;
		cursor: pointer;
	}

	.btn-export {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.4rem 0.8rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(34, 197, 94, 0.3);
		background: rgba(34, 197, 94, 0.1);
		color: #22c55e;
		cursor: pointer;
		font-size: 0.75rem;
		white-space: nowrap;
		transition: all 0.2s;
	}

	.btn-export:hover:not(:disabled) {
		background: rgba(34, 197, 94, 0.2);
		border-color: rgba(34, 197, 94, 0.5);
	}

	.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }

	.security-score-card {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 1rem;
		padding: 1rem;
	}

	.score-circle {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		border: 4px solid;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
	}

	.score-number {
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1;
	}

	.score-max {
		font-size: 0.6rem;
		color: #64748b;
	}

	.score-title {
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.security-checks {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.security-check {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
	}

	.security-check.pass {
		background: rgba(34, 197, 94, 0.05);
		border-color: rgba(34, 197, 94, 0.2);
	}

	.security-check.fail {
		background: rgba(239, 68, 68, 0.05);
		border-color: rgba(239, 68, 68, 0.2);
	}

	.check-icon { font-size: 0.9rem; }
	.check-label { font-size: 0.75rem; color: #e2e8f0; }

	.antibot-warning {
		background: rgba(239, 68, 68, 0.08);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: 0.5rem;
		padding: 0.75rem 1rem;
		margin-top: 0.75rem;
	}

	.warning-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.5rem;
	}

	.warning-icon { font-size: 1.1rem; }
	.warning-title { font-size: 0.85rem; font-weight: 600; color: #f87171; }

	.antibot-details {
		margin-top: 0.5rem;
	}

	.antibot-detail-item {
		font-size: 0.75rem;
		color: #fca5a5;
		padding: 0.15rem 0;
	}

	.antibot-safe {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: rgba(34, 197, 94, 0.08);
		border: 1px solid rgba(34, 197, 94, 0.2);
		border-radius: 0.5rem;
		margin-top: 0.75rem;
		font-size: 0.8rem;
		color: #86efac;
	}

	.safe-icon { font-size: 1rem; }

	.subdomain-list {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	.subdomain-item {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.4);
		transition: all 0.2s;
	}

	.subdomain-item:hover {
		background: rgba(15, 23, 42, 0.7);
		border-color: rgba(59, 130, 246, 0.3);
	}

	.subdomain-icon { font-size: 0.9rem; }
	.subdomain-name { font-size: 0.8rem; color: #e2e8f0; }

	@media (max-width: 768px) {
		.content-grid {
			grid-template-columns: 1fr;
		}

		.overview-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.mode-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.target-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
