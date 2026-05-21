<script lang="ts">
	import { page } from '$app/state';
	import { tr } from '$lib/i18n';

	let currentPath: string = $derived(page.url.pathname);

	interface NavItem {
		path: string;
		icon: string;
		labelKey: string;
	}

	interface NavCategory {
		id: string;
		icon: string;
		labelKey: string;
		items: NavItem[];
	}

	const categories: NavCategory[] = [
		{
			id: 'general',
			icon: '\u{1F3E0}',
			labelKey: 'sidebar.categories.general',
			items: [
				{ path: '/', icon: '\u{1F3E0}', labelKey: 'sidebar.dashboard' },
				{ path: '/tools/target_manager', icon: '\u{1F3AF}', labelKey: 'sidebar.targetManager' },
			]
		},
		{
			id: 'network',
			icon: '\u{1F310}',
			labelKey: 'sidebar.categories.network',
			items: [
				{ path: '/tools/port_scanner', icon: '\u{1F50D}', labelKey: 'sidebar.portScanner' },
				{ path: '/tools/ping', icon: '\u{1F4E1}', labelKey: 'sidebar.ping' },
				{ path: '/tools/dns_query', icon: '\u{1F310}', labelKey: 'sidebar.dnsQuery' },
				{ path: '/tools/host_to_ip', icon: '\u{1F517}', labelKey: 'sidebar.hostToIp' },
				{ path: '/tools/whois', icon: '\u{1F4CB}', labelKey: 'sidebar.whois' },
				{ path: '/tools/ip_geo', icon: '\u{1F30D}', labelKey: 'sidebar.ipGeo' },
				{ path: '/tools/ssl_checker', icon: '\u{1F512}', labelKey: 'sidebar.sslChecker' },
				{ path: '/tools/site_checker', icon: '\u{1F310}', labelKey: 'sidebar.siteChecker' },
				{ path: '/tools/network_discovery', icon: '\u{1F310}', labelKey: 'sidebar.networkDiscovery' },
				{ path: '/tools/wifi_scanner', icon: '\u{1F4F6}', labelKey: 'sidebar.wifiScanner' },
				{ path: '/tools/dns_analyzer', icon: '\u{1F50D}', labelKey: 'sidebar.dnsAnalyzer' },
			]
		},
		{
			id: 'web',
			icon: '\u{1F577}\u{FE0F}',
			labelKey: 'sidebar.categories.web',
			items: [
				{ path: '/tools/web_crawler', icon: '\u{1F577}\u{FE0F}', labelKey: 'sidebar.webCrawler' },
				{ path: '/tools/tech_detector', icon: '\u{1F52C}', labelKey: 'sidebar.techDetector' },
				{ path: '/tools/dir_scanner', icon: '\u{1F4C2}', labelKey: 'sidebar.dirScanner' },
				{ path: '/tools/param_discovery', icon: '\u{2699}\u{FE0F}', labelKey: 'sidebar.paramDiscovery' },
				{ path: '/tools/admin_finder', icon: '\u{1F510}', labelKey: 'sidebar.adminFinder' },
				{ path: '/tools/subdomain_enum', icon: '\u{1F310}', labelKey: 'sidebar.subdomainEnum' },
				{ path: '/tools/subdomain_takeover', icon: '\u{1F513}', labelKey: 'sidebar.subdomainTakeover' },
			]
		},
		{
			id: 'vuln',
			icon: '\u{1F489}',
			labelKey: 'sidebar.categories.vuln',
			items: [
				{ path: '/tools/sqli_scanner', icon: '\u{1F489}', labelKey: 'sidebar.sqliScanner' },
				{ path: '/tools/xss_scanner', icon: '\u{1F4A5}', labelKey: 'sidebar.xssScanner' },
				{ path: '/tools/command_injection', icon: '\u{1F489}', labelKey: 'sidebar.commandInjection' },
				{ path: '/tools/cors_checker', icon: '\u{1F310}', labelKey: 'sidebar.corsChecker' },
				{ path: '/tools/open_redirect', icon: '\u{21AA}\u{FE0F}', labelKey: 'sidebar.openRedirect' },
				{ path: '/tools/cve_lookup', icon: '\u{1F6D1}', labelKey: 'sidebar.cveLookup' },
				{ path: '/tools/secret_scanner', icon: '\u{1F511}', labelKey: 'sidebar.secretScanner' },
				{ path: '/tools/cookie_analyzer', icon: '\u{1F36A}', labelKey: 'sidebar.cookieAnalyzer' },
			]
		},
		{
			id: 'security',
			icon: '\u{1F6E1}\u{FE0F}',
			labelKey: 'sidebar.categories.security',
			items: [
				{ path: '/tools/security_headers', icon: '\u{1F6E1}\u{FE0F}', labelKey: 'sidebar.secHeaders' },
				{ path: '/tools/waf_detector', icon: '\u{1F6E1}\u{FE0F}', labelKey: 'sidebar.wafDetector' },
				{ path: '/tools/idn_checker', icon: '\u{1F524}', labelKey: 'sidebar.idnChecker' },
				{ path: '/tools/email_verifier', icon: '\u{1F4E7}', labelKey: 'sidebar.emailVerifier' },
				{ path: '/tools/username_osint', icon: '\u{1F464}', labelKey: 'sidebar.usernameOsint' },
			]
		},
		{
			id: 'crypto',
			icon: '\u{1F510}',
			labelKey: 'sidebar.categories.crypto',
			items: [
				{ path: '/tools/encoder', icon: '\u{1F510}', labelKey: 'sidebar.encoder' },
				{ path: '/tools/hash_identifier', icon: '\u{1F50D}', labelKey: 'sidebar.hashIdentifier' },
				{ path: '/tools/hash_cracker', icon: '\u{1F513}', labelKey: 'sidebar.hashCracker' },
				{ path: '/tools/steganography', icon: '\u{1F5BC}', labelKey: 'sidebar.steganography' },
				{ path: '/tools/brute_force', icon: '\u{1F510}', labelKey: 'sidebar.bruteForce' },
				{ path: '/tools/metadata_extractor', icon: '\u{1F4CB}', labelKey: 'sidebar.metadataExtractor' },
				{ path: '/tools/password', icon: '\u{1F511}', labelKey: 'sidebar.passwordGenerator' },
				{ path: '/tools/wordlist_generator', icon: '\u{1F4DA}', labelKey: 'sidebar.wordlistGenerator' },
				{ path: '/tools/zip', icon: '\u{1F4E6}', labelKey: 'sidebar.zipExtractor' },
			]
		},
		{
			id: 'advanced',
			icon: '\u{1F680}',
			labelKey: 'sidebar.categories.advanced',
			items: [
				{ path: '/tools/cloud_audit', icon: '\u{2601}\u{FE0F}', labelKey: 'sidebar.cloudAudit' },
				{ path: '/tools/apk_analysis', icon: '\u{1F4F1}', labelKey: 'sidebar.apkAnalysis' },
				{ path: '/tools/ddos_tester', icon: '\u{26A1}', labelKey: 'sidebar.ddosTester' },
				{ path: '/tools/privilege_esc_check', icon: '\u{1F513}', labelKey: 'sidebar.privilegeEscCheck' },
				{ path: '/tools/binary_analyzer', icon: '\u{1F52C}', labelKey: 'sidebar.binaryAnalyzer' },
				{ path: '/tools/reverse_engineer', icon: '\u{1F527}', labelKey: 'sidebar.reverseEngineer' },
				{ path: '/tools/wifi_deauth_detector', icon: '\u{1F4E1}', labelKey: 'sidebar.wifiDeauthDetector' },
				{ path: '/tools/exploit_framework', icon: '\u{2694}\u{FE0F}', labelKey: 'sidebar.exploitFramework' },
				{ path: '/tools/post_exploitation', icon: '\u{1F3AF}', labelKey: 'sidebar.postExploitation' },
				{ path: '/tools/payload_injector', icon: '\u{1F489}', labelKey: 'sidebar.payloadInjector' },
				{ path: '/tools/phishing_detector', icon: '\u{1F41F}', labelKey: 'sidebar.phishingDetector' },
				{ path: '/tools/anonymity_checker', icon: '\u{1F575}\u{FE0F}', labelKey: 'sidebar.anonymityChecker' },
				{ path: '/tools/forensics_analyzer', icon: '\u{1F52C}', labelKey: 'sidebar.forensicsAnalyzer' },
				{ path: '/tools/ad_audit', icon: '\u{1F3E2}', labelKey: 'sidebar.adAudit' },
				{ path: '/tools/mobile_security', icon: '\u{1F4F1}', labelKey: 'sidebar.mobileSecurity' },
				{ path: '/tools/asset_search', icon: '\u{1F50D}', labelKey: 'sidebar.assetSearch' },
				{ path: '/tools/reverse_ip', icon: '\u{1F504}', labelKey: 'sidebar.reverseIp' },
				{ path: '/tools/cf_bypass', icon: '\u{2601}\u{FE0F}', labelKey: 'sidebar.cfBypass' },
				{ path: '/tools/social_finder', icon: '\u{1F464}', labelKey: 'sidebar.socialFinder' },
				{ path: '/tools/osint_gather', icon: '\u{1F575}\u{FE0F}', labelKey: 'sidebar.osintGather' },
				{ path: '/tools/rat_tool', icon: '\u{1F5A5}\u{FE0F}', labelKey: 'sidebar.ratTool' },
				{ path: '/tools/bluetooth_scanner', icon: '\u{1F4E1}', labelKey: 'sidebar.bluetoothScanner' },
				{ path: '/tools/memory_forensics', icon: '\u{1F4BE}', labelKey: 'sidebar.memoryForensics' },
				{ path: '/tools/firmware_analyzer', icon: '\u{1F4E6}', labelKey: 'sidebar.firmwareAnalyzer' },
				{ path: '/tools/social_engineering', icon: '\u{1F3AD}', labelKey: 'sidebar.socialEngineering' },
			]
		},
	];

	let expandedCategories: Record<string, boolean> = $state({});

	$effect(() => {
		for (const cat of categories) {
			if (cat.items.some(item => currentPath === item.path)) {
				expandedCategories[cat.id] = true;
			}
		}
	});

	function toggleCategory(id: string) {
		expandedCategories[id] = !expandedCategories[id];
	}

	function isExpanded(id: string): boolean {
		return !!expandedCategories[id];
	}

	function hasActiveItem(cat: NavCategory): boolean {
		return cat.items.some(item => currentPath === item.path);
	}
</script>

<aside class="sidebar">
	<nav class="nav">
		{#each categories as cat}
			<div class="nav-category" class:has-active={hasActiveItem(cat)}>
				<button
					class="category-header"
					class:expanded={isExpanded(cat.id)}
					class:active={hasActiveItem(cat)}
					onclick={() => toggleCategory(cat.id)}
				>
					<span class="category-icon">{cat.icon}</span>
					<span class="category-text">{$tr(cat.labelKey)}</span>
					<span class="category-arrow" class:rotated={isExpanded(cat.id)}>&#x276F;</span>
				</button>

				{#if isExpanded(cat.id)}
					<div class="category-items">
						{#each cat.items as item}
							<a
								href={item.path}
								class="nav-item"
								class:active={currentPath === item.path}
							>
								<span class="nav-icon">{item.icon}</span>
								<span class="nav-text">{$tr(item.labelKey)}</span>
							</a>
						{/each}
					</div>
				{/if}
			</div>
		{/each}
	</nav>
</aside>

<style>
	.sidebar {
		width: 250px;
		flex-shrink: 0;
		background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
		border-right: 1px solid rgba(168, 85, 247, 0.2);
		display: flex;
		flex-direction: column;
		overflow-y: auto;
	}

	.nav {
		flex: 1;
		padding: 1rem 0;
		overflow-y: auto;
	}

	.nav-category {
		margin-bottom: 0.25rem;
	}

	.category-header {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		width: 100%;
		padding: 0.7rem 1rem;
		border: none;
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		transition: all 0.2s ease;
		font-size: 0.85rem;
		font-weight: 600;
		text-align: left;
	}

	.category-header:hover {
		background: rgba(168, 85, 247, 0.08);
		color: var(--text-primary);
	}

	.category-header.active {
		color: var(--primary);
	}

	.category-header.expanded {
		color: var(--text-primary);
	}

	.category-icon {
		font-size: 1.1rem;
		width: 22px;
		text-align: center;
		flex-shrink: 0;
	}

	.category-text {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.category-arrow {
		font-size: 0.9rem;
		transition: transform 0.25s ease;
		flex-shrink: 0;
		opacity: 0.4;
		display: inline-block;
	}

	.category-arrow.rotated {
		transform: rotate(90deg);
		opacity: 0.8;
	}

	.category-items {
		overflow: hidden;
		animation: slideDown 0.2s ease;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			max-height: 0;
		}
		to {
			opacity: 1;
			max-height: 500px;
		}
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.55rem 1rem 0.55rem 2.2rem;
		color: var(--text-secondary);
		text-decoration: none;
		transition: all 0.2s ease;
		position: relative;
		font-size: 0.82rem;
	}

	.nav-item:hover {
		background: rgba(168, 85, 247, 0.1);
		color: var(--text-primary);
	}

	.nav-item.active {
		background: linear-gradient(90deg, rgba(168, 85, 247, 0.2) 0%, transparent 100%);
		color: var(--primary);
	}

	.nav-item.active::before {
		content: '';
		position: absolute;
		left: 0;
		top: 0;
		bottom: 0;
		width: 3px;
		background: linear-gradient(180deg, #a855f7, #6366f1);
		border-radius: 0 2px 2px 0;
	}

	.nav-icon {
		font-size: 1rem;
		width: 20px;
		text-align: center;
		flex-shrink: 0;
	}

	.nav-text {
		flex: 1;
		font-weight: 500;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
</style>
