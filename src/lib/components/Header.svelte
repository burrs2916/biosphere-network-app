<script lang="ts">
  import { tr, setLocale, locale, SUPPORTED_LOCALES, initLocale } from '$lib/i18n';
  import { onMount } from 'svelte';

  let showLangMenu = false;

  $: currentLocale = $locale;

  onMount(() => {
    initLocale();
  });

  function handleKeyPress(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      showLangMenu = false;
    }
  }

  function handleWindowClick() {
    if (showLangMenu) {
      showLangMenu = false;
    }
  }

  function handleLangSwitch(e: MouseEvent, newLocale: 'en' | 'zh') {
    e.stopPropagation();
    setLocale(newLocale);
    showLangMenu = false;
  }

  function toggleLangMenu(e: MouseEvent) {
    e.stopPropagation();
    showLangMenu = !showLangMenu;
  }
</script>

<svelte:window on:keydown={handleKeyPress} on:click={handleWindowClick} />

<header class="header">
  <div class="header-left">
    <div class="logo">
      <img src="/logo.png" alt="Biosphere" class="logo-icon" />
      <span class="logo-text">Biosphere Network</span>
    </div>
  </div>

  <div class="header-right">
    <div class="lang-switcher">
      <button class="icon-btn" title={$tr('common.settings')} on:click={toggleLangMenu}>
        🌐
      </button>
      {#if showLangMenu}
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="lang-dropdown" on:click|stopPropagation>
          {#each SUPPORTED_LOCALES as loc}
            <button
              class="lang-option"
              class:active={currentLocale === loc.code}
              on:click={(e) => handleLangSwitch(e, loc.code)}
            >
              <span>{loc.nativeName}</span>
              {#if currentLocale === loc.code}
                <span class="check">✓</span>
              {/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</header>

<style>
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 2rem;
    background: linear-gradient(180deg, rgba(26, 26, 46, 0.95) 0%, rgba(26, 26, 46, 0.8) 100%);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(168, 85, 247, 0.2);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .header-left {
    flex: 1;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .logo-icon {
    width: 2.5rem;
    height: 2.5rem;
    object-fit: contain;
  }

  .logo-text {
    font-size: 1.25rem;
    font-weight: 700;
    background: linear-gradient(135deg, #a855f7, #6366f1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .header-right {
    flex: 1;
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    align-items: center;
  }

  .icon-btn {
    background: rgba(168, 85, 247, 0.1);
    border: 1px solid rgba(168, 85, 247, 0.2);
    border-radius: 8px;
    padding: 0.5rem;
    font-size: 1.25rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .icon-btn:hover {
    background: rgba(168, 85, 247, 0.2);
    border-color: #a855f7;
    transform: translateY(-2px);
  }

  .lang-switcher {
    position: relative;
  }

  .lang-dropdown {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    background: #1a1a2e;
    border: 1px solid rgba(168, 85, 247, 0.3);
    border-radius: 10px;
    padding: 0.5rem;
    min-width: 140px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    z-index: 200;
  }

  .lang-option {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 0.875rem;
    cursor: pointer;
    border-radius: 6px;
    transition: all 0.15s;
  }

  .lang-option:hover {
    background: rgba(168, 85, 247, 0.15);
    color: var(--text-primary);
  }

  .lang-option.active {
    color: #a855f7;
    font-weight: 600;
  }

  .lang-option .check {
    color: #a855f7;
    font-size: 0.75rem;
  }
</style>
