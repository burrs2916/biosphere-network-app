<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { open, save } from '@tauri-apps/plugin-dialog';
  import { readFile, writeFile } from '@tauri-apps/plugin-fs';
  import { tr } from '$lib/i18n';
import ToolHistory from '$lib/components/ToolHistory.svelte';
	import ToolHelp from '$lib/components/ToolHelp.svelte';

  interface EncoderResult {
    success: boolean;
    input: string;
    output: string;
    encoding_type: string;
    operation: string;
    error: string | null;
  }

  interface FileInfo {
    name: string;
    size: number;
    path: string;
  }

  let mode: 'text' | 'file' = $state('text');
  let activeMainTab = $state('analyze');
  let historyComponent: ToolHistory = $state(null!);
  let toolMode: 'encode' | 'hash' = $state('encode');
  let encodingType = $state('base64');
  let hashType = $state('md5');
  let operation = $state('encode');
  let input = $state('');
  let output = $state('');
  let processing = $state(false);
  let error = $state('');
  let showHelpModal = $state(false);
  let fileInfo: FileInfo | null = $state(null);
  let noChange = $state(false);
  let outputFileInfo: FileInfo | null = $state(null);
  let autoDetectedType = '';

  function formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  async function selectFile() {
    try {
      console.log('Opening file dialog...');
      const selected = await open({
        multiple: false,
        title: $tr('encoder.file.selectFile')
      });

      console.log('Selected:', selected);

      if (selected === null) {
        console.log('User cancelled file selection');
        return;
      }

      // In Tauri 2.x, open() returns string | string[] | null directly
      const filePath = typeof selected === 'string' 
        ? selected 
        : (Array.isArray(selected) ? selected[0] : null);
      
      if (!filePath) {
        console.log('No file path returned');
        return;
      }

      console.log('File path:', filePath);
      
      const fileName = filePath.split('/').pop() || filePath.split('\\').pop() || 'Unknown';
      
      console.log('Reading file...');
      const fileData = await readFile(filePath);
      console.log('File read successfully, size:', fileData.length);
      
      fileInfo = {
        name: fileName,
        size: fileData.length,
        path: filePath
      };
      
      error = '';
      output = '';
      outputFileInfo = null;
    } catch (e) {
      console.error('Error in selectFile:', e);
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function processText() {
    if (mode === 'text') {
      if (!input.trim()) {
        error = $tr('encoder.error.emptyInput');
        return;
      }

      processing = true;
      error = '';
      output = '';
      noChange = false;

      try {
        if (toolMode === 'hash') {
          const result = await invoke<string>('compute_hash_command', {
            hashType,
            input
          });
          output = result;
          noChange = false;
        } else {
          const result = await invoke<EncoderResult>('encode_decode_command', {
            encodingType,
            operation,
            input
          });

          if (result.success) {
            output = result.output;
            noChange = (operation !== 'hash') && (input === output);
          } else {
            error = result.error || $tr('encoder.error.processing');
          }
        }
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      } finally {
        processing = false;
      }
    } else {
      if (!fileInfo) {
        error = $tr('encoder.error.noFile');
        return;
      }

      processing = true;
      error = '';
      output = '';

      try {
        const fileData = await readFile(fileInfo.path);
        
        if (operation === 'encode') {
          const result = await invoke<string>('encode_file_command', {
            encodingType,
            fileData: Array.from(fileData)
          });
          output = result;
          outputFileInfo = null;
        } else {
          const result = await invoke<number[]>('decode_file_command', {
            encodingType,
            encodedData: input
          });
          const uint8Array = new Uint8Array(result);
          outputFileInfo = {
            name: `decoded_${fileInfo.name}`,
            size: uint8Array.length,
            path: ''
          };
          output = $tr('encoder.file.decodedSuccess', { size: formatFileSize(uint8Array.length) });
        }
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      } finally {
        processing = false;
      }
    }
  }

  async function saveFile() {
    if (!output && !outputFileInfo) return;

    try {
      const extension = encodingType === 'base64' ? 'txt' : 'hex';
      const defaultName = fileInfo 
        ? `${fileInfo.name}.${extension}`
        : `encoded.${extension}`;

      const savePath = await save({
        defaultPath: defaultName,
        title: $tr('encoder.file.saveFile')
      });

      if (savePath) {
        if (operation === 'encode') {
          const encoder = new TextEncoder();
          await writeFile(savePath, encoder.encode(output));
        } else if (outputFileInfo) {
          const result = await invoke<number[]>('decode_file_command', {
            encodingType,
            encodedData: input
          });
          const uint8Array = new Uint8Array(result);
          await writeFile(savePath, uint8Array);
        }
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  function swapInputOutput() {
    if (mode === 'text') {
      const temp = input;
      input = output;
      output = temp;
      operation = operation === 'encode' ? 'decode' : 'encode';
    }
  }

  async function autoDetectEncoding() {
    if (!input.trim()) {
      autoDetectedType = '';
      return;
    }

    try {
      const result = await invoke<{encoding_type: string, confidence: number}>('detect_encoding_command', {
        input
      });
      
      if (result.encoding_type) {
        autoDetectedType = result.encoding_type;
        encodingType = result.encoding_type;
      }
    } catch (e) {
      console.error('Auto-detection failed:', e);
      autoDetectedType = '';
    }
  }

  function clearAll() {
    input = '';
    output = '';
    error = '';
    fileInfo = null;
    outputFileInfo = null;
    autoDetectedType = '';
  }

  function copyOutput() {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  }
</script>

<svelte:head>
  <title>{$tr('encoder.title')} - Biosphere Network Tools</title>
</svelte:head>

<div class="nd-page">
	<div class="page-header">
		<div class="header-left">
			<a href="/" class="back-link">{$tr('common.backToHome')}</a>
			<h1 class="page-title">🔐 {$tr('encoder.title')}</h1>
			<p class="page-subtitle">{$tr('encoder.subtitle')}</p>
		</div>
	</div>

	<div class="tabs">
		<button class="tab-btn {activeMainTab === 'analyze' ? 'active' : ''}" onclick={() => activeMainTab = 'analyze'}>
			<span class="tab-icon">🔍</span> {$tr('encoder.tabs.convert')}
		</button>
		<button class="tab-btn {activeMainTab === 'history' ? 'active' : ''}" onclick={() => activeMainTab = 'history'}>
			<span class="tab-icon">📋</span> {$tr('encoder.tabs.history')}
		</button>
		<button class="tab-btn {activeMainTab === 'help' ? 'active' : ''}" onclick={() => activeMainTab = 'help'}>
			<span class="tab-icon">📖</span> {$tr('encoder.tabs.help')}
		</button>
	</div>
	{#if activeMainTab === 'analyze'}

  <div class="content-grid">
    <div class="input-section">
      <div class="section-card">
        <h2 class="section-title">{$tr('encoder.config.title')}</h2>

        <div class="form-group">
          <label class="form-label">{$tr('encoder.toolMode.encodeDecode')}</label>
          <div class="mode-buttons">
            <button
              class="mode-btn {toolMode === 'encode' ? 'active' : ''}"
              onclick={() => { toolMode = 'encode'; operation = 'encode'; }}
            >
              🔐 {$tr('encoder.toolMode.encodeDecode')}
            </button>
            <button
              class="mode-btn {toolMode === 'hash' ? 'active' : ''}"
              onclick={() => toolMode = 'hash'}
            >
              #️⃣ {$tr('encoder.toolMode.hashCalc')}
            </button>
          </div>
        </div>

        {#if toolMode === 'encode'}
          <div class="form-group">
            <label class="form-label">{$tr('encoder.labels.mode')}</label>
            <div class="mode-buttons">
              <button
                class="mode-btn {mode === 'text' ? 'active' : ''}"
                onclick={() => { mode = 'text'; clearAll(); }}
              >
                📝 {$tr('encoder.mode.text')}
              </button>
              <button
                class="mode-btn {mode === 'file' ? 'active' : ''}"
                onclick={() => { mode = 'file'; clearAll(); }}
              >
                📁 {$tr('encoder.mode.file')}
              </button>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">{$tr('encoder.labels.encodingType')}</label>
            <div class="encoding-buttons">
              <button
                class="encoding-btn {encodingType === 'base64' ? 'active' : ''}"
                onclick={() => encodingType = 'base64'}
              >
                Base64
              </button>
              <button
                class="encoding-btn {encodingType === 'base64url' ? 'active' : ''}"
                onclick={() => encodingType = 'base64url'}
              >
                Base64URL
              </button>
              <button
                class="encoding-btn {encodingType === 'url' ? 'active' : ''}"
                onclick={() => encodingType = 'url'}
                disabled={mode === 'file'}
                title={mode === 'file' ? $tr('encoder.file.urlNotSupported') : ''}
              >
                URL
              </button>
              <button
                class="encoding-btn {encodingType === 'html' ? 'active' : ''}"
                onclick={() => encodingType = 'html'}
                disabled={mode === 'file'}
                title={mode === 'file' ? $tr('encoder.file.htmlNotSupported') : ''}
              >
                HTML
              </button>
              <button
                class="encoding-btn {encodingType === 'hex' ? 'active' : ''}"
                onclick={() => encodingType = 'hex'}
              >
                Hex
              </button>
              <button
                class="encoding-btn {encodingType === 'base32' ? 'active' : ''}"
                onclick={() => encodingType = 'base32'}
              >
                Base32
              </button>
              <button
                class="encoding-btn {encodingType === 'base58' ? 'active' : ''}"
                onclick={() => encodingType = 'base58'}
              >
                Base58
              </button>
              <button
                class="encoding-btn {encodingType === 'jwt' ? 'active' : ''}"
                onclick={() => { encodingType = 'jwt'; operation = 'decode'; }}
                disabled={mode === 'file'}
                title={mode === 'file' ? 'JWT only supports text mode' : ''}
              >
                JWT
              </button>
              <button
                class="encoding-btn {encodingType === 'rot13' ? 'active' : ''}"
                onclick={() => encodingType = 'rot13'}
                disabled={mode === 'file'}
                title={mode === 'file' ? 'ROT13 only supports text mode' : ''}
              >
                ROT13
              </button>
              <button
                class="encoding-btn {encodingType === 'rot47' ? 'active' : ''}"
                onclick={() => encodingType = 'rot47'}
                disabled={mode === 'file'}
                title={mode === 'file' ? 'ROT47 only supports text mode' : ''}
              >
                ROT47
              </button>
              <button
                class="encoding-btn {encodingType === 'unicode' ? 'active' : ''}"
                onclick={() => encodingType = 'unicode'}
                disabled={mode === 'file'}
                title={mode === 'file' ? 'Unicode only supports text mode' : ''}
              >
                Unicode
              </button>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">{$tr('encoder.labels.operation')}</label>
            <div class="operation-buttons">
              <button
                class="operation-btn {operation === 'encode' ? 'active' : ''}"
                onclick={() => operation = 'encode'}
              >
                🔒 {$tr('encoder.buttons.encode')}
              </button>
              <button
                class="operation-btn {operation === 'decode' ? 'active' : ''}"
                onclick={() => operation = 'decode'}
              >
                🔓 {$tr('encoder.buttons.decode')}
              </button>
              <button
                class="operation-btn"
                onclick={autoDetectEncoding}
                disabled={!input.trim()}
                title={$tr('encoder.autoDetectTitle')}
              >
                🔍 {$tr('encoder.autoDetect')}
              </button>
            </div>
          </div>
        {:else}
          <div class="form-group">
            <label class="form-label">{$tr('encoder.hashAlgorithm')}</label>
            <div class="encoding-buttons">
              <button
                class="encoding-btn {hashType === 'md5' ? 'active' : ''}"
                onclick={() => hashType = 'md5'}
              >
                MD5
              </button>
              <button
                class="encoding-btn {hashType === 'sha1' ? 'active' : ''}"
                onclick={() => hashType = 'sha1'}
              >
                SHA-1
              </button>
              <button
                class="encoding-btn {hashType === 'sha256' ? 'active' : ''}"
                onclick={() => hashType = 'sha256'}
              >
                SHA-256
              </button>
              <button
                class="encoding-btn {hashType === 'sha384' ? 'active' : ''}"
                onclick={() => hashType = 'sha384'}
              >
                SHA-384
              </button>
              <button
                class="encoding-btn {hashType === 'sha512' ? 'active' : ''}"
                onclick={() => hashType = 'sha512'}
              >
                SHA-512
              </button>
            </div>
          </div>
        {/if}

        <div class="form-group">
          <label class="form-label" for="input">
            {#if mode === 'text'}
              {$tr('encoder.labels.input')}
            {:else}
              {$tr('encoder.labels.fileInput')}
            {/if}
          </label>
          
          {#if mode === 'text'}
            <textarea
              id="input"
              bind:value={input}
              placeholder={$tr('encoder.placeholder.input')}
              class="form-textarea"
              rows="8"
              disabled={processing}
            ></textarea>
          {:else}
            <div class="file-input-area">
              {#if fileInfo}
                <div class="file-info-card">
                  <div class="file-icon">📄</div>
                  <div class="file-details">
                    <div class="file-name">{fileInfo.name}</div>
                    <div class="file-size">{formatFileSize(fileInfo.size)}</div>
                  </div>
                  <button
                    class="btn btn-small btn-remove"
                    onclick={() => { fileInfo = null; error = ''; output = ''; }}
                    disabled={processing}
                  >
                    ✕
                  </button>
                </div>
              {:else}
                <button
                  class="btn btn-file-select"
                  onclick={selectFile}
                  disabled={processing}
                >
                  📁 {$tr('encoder.buttons.selectFile')}
                </button>
              {/if}
              
              {#if operation === 'decode'}
                <textarea
                  id="input"
                  bind:value={input}
                  placeholder={$tr('encoder.placeholder.encodedInput')}
                  class="form-textarea"
                  rows="4"
                  disabled={processing}
                  style="margin-top: 1rem;"
                ></textarea>
              {/if}
            </div>
          {/if}
        </div>

        <div class="button-group">
          <button
            class="btn btn-primary"
            onclick={processText}
            disabled={processing || (mode === 'text' && !input.trim()) || (mode === 'file' && !fileInfo && operation === 'encode') || (mode === 'file' && !input.trim() && operation === 'decode')}
          >
            {#if processing}
              ⏳ {$tr('encoder.buttons.processing')}
            {:else}
              ⚡ {$tr('encoder.buttons.process')}
            {/if}
          </button>
          <button
            class="btn btn-secondary"
            onclick={clearAll}
            disabled={processing}
          >
            🗑️ {$tr('encoder.buttons.clear')}
          </button>
        </div>
      </div>
    </div>

    <div class="result-section">
      <div class="section-card">
        <div class="result-header">
          <h2 class="section-title">{$tr('encoder.result.title')}</h2>
          {#if output || outputFileInfo}
            <div class="result-actions">
              {#if mode === 'text'}
                <button
                  class="btn btn-small"
                  onclick={swapInputOutput}
                  title={$tr('encoder.buttons.swap')}
                >
                  🔄 {$tr('encoder.buttons.swap')}
                </button>
              {/if}
              {#if mode === 'text' || (mode === 'file' && operation === 'encode')}
                <button
                  class="btn btn-small"
                  onclick={copyOutput}
                  title={$tr('encoder.buttons.copy')}
                >
                  📋 {$tr('encoder.buttons.copy')}
                </button>
              {/if}
              {#if mode === 'file'}
                <button
                  class="btn btn-small btn-save"
                  onclick={saveFile}
                  title={$tr('encoder.buttons.saveFile')}
                >
                  💾 {$tr('encoder.buttons.saveFile')}
                </button>
              {/if}
            </div>
          {/if}
        </div>

        {#if error}
          <div class="error-card">
            <div class="error-header">
              <span class="error-icon">⚠️</span>
              <span class="error-title">{$tr('encoder.error.title')}</span>
            </div>
            <div class="error-message">{error}</div>
          </div>
        {:else if outputFileInfo}
          <div class="output-file-info">
            <div class="file-icon">✅</div>
            <div class="file-details">
              <div class="file-name">{outputFileInfo.name}</div>
              <div class="file-size">{formatFileSize(outputFileInfo.size)}</div>
            </div>
          </div>
        {:else if output}
          {#if noChange}
            <div class="info-card">
              <div class="info-icon">ℹ️</div>
              <div class="info-text">
                <strong>{$tr('encoder.info.noChange')}</strong>
                <p>{$tr('encoder.info.noChangeDesc')}</p>
              </div>
            </div>
          {/if}
          <div class="output-container">
            <textarea
              bind:value={output}
              class="form-textarea output-textarea"
              rows="8"
              readonly
            ></textarea>
          </div>
        {:else}
          <div class="empty-result">
            <div class="empty-icon">📝</div>
            <p class="empty-text">{$tr('encoder.result.empty')}</p>
            <p class="empty-hint">{$tr('encoder.result.hint')}</p>
          </div>
        {/if}
      </div>
    </div>
  </div>

{#if showHelpModal}
  <div 
    class="modal-overlay" 
    role="button"
    tabindex="-1"
    onclick={() => showHelpModal = false}
    onkeydown={(e) => e.key === 'Escape' && (showHelpModal = false)}
  >
    <div 
      class="modal-content" 
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
    >
      <div class="modal-header">
        <h2>{$tr('encoder.helpModal.title')}</h2>
        <button class="modal-close" onclick={() => showHelpModal = false}>✕</button>
      </div>
      
      <div class="modal-body">
        <section class="help-section">
          <h3>{$tr('encoder.helpModal.overview')}</h3>
          <p>{$tr('encoder.helpModal.overviewText')}</p>
        </section>

        <section class="help-section">
          <h3>{$tr('encoder.helpModal.encodingTypes')}</h3>
          <ul>
            <li><strong>Base64：</strong>{$tr('encoder.helpModal.base64Desc')}</li>
            <li><strong>Base64URL：</strong>{$tr('encoder.helpModal.base64urlDesc')}</li>
            <li><strong>URL：</strong>{$tr('encoder.helpModal.urlDesc')}</li>
            <li><strong>HTML：</strong>{$tr('encoder.helpModal.htmlDesc')}</li>
            <li><strong>Hex：</strong>{$tr('encoder.helpModal.hexDesc')}</li>
            <li><strong>JWT：</strong>{$tr('encoder.helpModal.jwtDesc')}</li>
            <li><strong>ROT13：</strong>{$tr('encoder.helpModal.rot13Desc')}</li>
            <li><strong>ROT47：</strong>{$tr('encoder.helpModal.rot47Desc')}</li>
            <li><strong>Unicode：</strong>{$tr('encoder.helpModal.unicodeDesc')}</li>
          </ul>
        </section>

        <section class="help-section">
          <h3>{$tr('encoder.helpModal.howToUse')}</h3>
          <ol>
            <li>{$tr('encoder.helpModal.step1')}</li>
            <li>{$tr('encoder.helpModal.step2')}</li>
            <li>{$tr('encoder.helpModal.step3')}</li>
            <li>{$tr('encoder.helpModal.step4')}</li>
            <li>{$tr('encoder.helpModal.step5')}</li>
          </ol>
        </section>

        <section class="help-section">
          <h3>{$tr('encoder.helpModal.tips')}</h3>
          <ul>
            <li>{$tr('encoder.helpModal.tip1')}</li>
            <li>{$tr('encoder.helpModal.tip2')}</li>
            <li>{$tr('encoder.helpModal.tip3')}</li>
            <li>{$tr('encoder.helpModal.tip4')}</li>
            <li>{$tr('encoder.helpModal.tip5')}</li>
          </ul>
        </section>

        <section class="help-section">
          <h3>{$tr('encoder.helpModal.examples')}</h3>
          <div class="example-grid">
            <div class="example-item">
              <strong>{$tr('encoder.examples.base64')}</strong>
              <code>Hello World → SGVsbG8gV29ybGQ=</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.base64url')}</strong>
              <code>Hello World → SGVsbG8gV29ybGQ</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.url')}</strong>
              <code>Hello World → Hello%20World</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.jwt')}</strong>
              <code>eyJhbGci... → &#123;"header": &#123;...&#125;, "payload": &#123;...&#125;&#125;</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.rot13')}</strong>
              <code>Hello → Uryyb</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.unicode')}</strong>
              <code>Hello → \u0048\u0065\u006c\u006c\u006f</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.html')}</strong>
              <code>&lt;div&gt; → &amp;lt;div&amp;gt;</code>
            </div>
            <div class="example-item">
              <strong>{$tr('encoder.examples.hex')}</strong>
              <code>Hello → 48656c6c6f</code>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
{/if}

{:else if activeMainTab === 'history'}
	<div class="section-card"><ToolHistory toolType="encoder" toolName={$tr('encoder.toolName')} bind:this={historyComponent} /></div>
{:else if activeMainTab === 'help'}
	<div class="section-card"><ToolHelp toolType="encoder" /></div>
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

	.content-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; }
	.input-section { display: flex; flex-direction: column; gap: 1rem; }

	.section-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(168, 85, 247, 0.15); border-radius: 0.75rem; padding: 1.25rem; }
	.section-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin: 0 0 1rem; }

	.form-group { margin-bottom: 1rem; }
	.form-label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.35rem; font-weight: 500; }

	.form-textarea {
		width: 100%; padding: 0.5rem 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.15);
		background: rgba(15, 23, 42, 0.8); color: #e2e8f0; font-size: 0.85rem; font-family: 'SF Mono', 'Fira Code', monospace;
		resize: vertical; box-sizing: border-box;
	}
	.form-textarea:focus { outline: none; border-color: rgba(168, 85, 247, 0.4); box-shadow: 0 0 0 2px rgba(168, 85, 247, 0.1); }

	.mode-buttons { display: flex; gap: 0.5rem; }
	.mode-btn {
		flex: 1; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.15);
		border-radius: 0.4rem; color: #94a3b8; font-size: 0.8rem; font-weight: 500; cursor: pointer; transition: all 0.2s;
	}
	.mode-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.mode-btn.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }

	.file-input-area { display: flex; flex-direction: column; gap: 1rem; }
	.file-info-card { display: flex; align-items: center; gap: 1rem; padding: 1rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 0.5rem; }
	.file-icon { font-size: 2rem; }
	.file-details { flex: 1; }
	.file-name { font-weight: 600; color: #f1f5f9; margin-bottom: 0.25rem; }
	.file-size { font-size: 0.8rem; color: #94a3b8; }

	.btn-file-select {
		width: 100%; padding: 2rem; background: rgba(168, 85, 247, 0.1); border: 2px dashed rgba(168, 85, 247, 0.3);
		border-radius: 0.5rem; color: #a855f7; font-size: 1rem; font-weight: 500; cursor: pointer; transition: all 0.2s;
	}
	.btn-file-select:hover { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.5); }

	.btn-remove { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
	.btn-remove:hover { background: rgba(239, 68, 68, 0.3); }
	.btn-save { background: rgba(16, 185, 129, 0.2); color: #10b981; }
	.btn-save:hover { background: rgba(16, 185, 129, 0.3); }

	.output-file-info { display: flex; align-items: center; gap: 1rem; padding: 1.5rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 0.5rem; }

	.encoding-buttons, .operation-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
	.encoding-btn, .operation-btn {
		flex: 1; min-width: 80px; padding: 0.5rem 0.75rem; background: rgba(15, 23, 42, 0.6);
		border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 0.4rem; color: #94a3b8;
		font-size: 0.8rem; font-weight: 500; cursor: pointer; transition: all 0.2s; text-align: center;
		display: flex; align-items: center; justify-content: center;
	}
	.encoding-btn:hover, .operation-btn:hover { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.encoding-btn.active, .operation-btn.active { border-color: rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.1); color: #c4b5fd; }

	.button-group { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
	.btn { padding: 0.6rem 1.25rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; }
	.btn-primary { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); color: white; }
	.btn-primary:hover:not(:disabled) { box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4); }
	.btn-secondary { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); color: #94a3b8; }
	.btn-secondary:hover:not(:disabled) { border-color: rgba(168, 85, 247, 0.3); color: #c4b5fd; }
	.btn-small { padding: 0.4rem 0.75rem; font-size: 0.8rem; }
	.btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
	.result-actions { display: flex; gap: 0.5rem; }
	.output-container { margin-top: 1rem; }
	.output-textarea { background: rgba(16, 185, 129, 0.05); border-color: rgba(16, 185, 129, 0.2); }

	.error-card { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 0.5rem; padding: 1rem; margin-top: 1rem; }
	.info-card { background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; display: flex; align-items: flex-start; gap: 0.75rem; }
	.info-icon { font-size: 1.5rem; flex-shrink: 0; }
	.info-text { flex: 1; }
	.info-text strong { color: #60a5fa; font-size: 0.85rem; display: block; margin-bottom: 0.25rem; }
	.info-text p { color: #94a3b8; font-size: 0.8rem; margin: 0; line-height: 1.5; }

	.error-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
	.error-icon { font-size: 1.25rem; }
	.error-title { font-weight: 600; color: #fca5a5; }
	.error-message { color: #d1d5db; font-size: 0.85rem; }

	.empty-result { text-align: center; padding: 3rem 1rem; }
	.empty-icon { font-size: 3rem; margin-bottom: 1rem; }
	.empty-text { font-size: 1rem; color: #94a3b8; margin-bottom: 0.5rem; }
	.empty-hint { font-size: 0.85rem; color: #64748b; }

	.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.75); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 2rem; }
	.modal-content { background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 1rem; max-width: 700px; width: 100%; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5); }
	.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1.5rem; border-bottom: 1px solid rgba(168, 85, 247, 0.15); }
	.modal-header h2 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; margin: 0; }
	.modal-close { background: rgba(255, 255, 255, 0.1); border: none; color: #e5e7eb; width: 2rem; height: 2rem; border-radius: 0.5rem; cursor: pointer; font-size: 1.25rem; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }
	.modal-close:hover { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
	.modal-body { padding: 1.5rem; }

	.help-section { margin-bottom: 1.5rem; }
	.help-section:last-child { margin-bottom: 0; }
	.help-section h3 { font-size: 1rem; font-weight: 600; color: #a855f7; margin-bottom: 0.75rem; }
	.help-section p { color: #d1d5db; line-height: 1.6; margin: 0; }
	.help-section ul, .help-section ol { color: #d1d5db; line-height: 1.8; margin: 0; padding-left: 1.5rem; }
	.help-section li { margin-bottom: 0.5rem; }
	.help-section li strong { color: #f1f5f9; }

	.example-grid { display: grid; gap: 0.75rem; }
	.example-item { background: rgba(15, 23, 42, 0.6); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.1); }
	.example-item strong { display: block; color: #f1f5f9; margin-bottom: 0.5rem; font-size: 0.85rem; }
	.example-item code { display: block; color: #10b981; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; background: rgba(16, 185, 129, 0.1); padding: 0.5rem; border-radius: 0.25rem; word-break: break-all; }

	@media (max-width: 1024px) { .content-grid { grid-template-columns: 1fr; } }
</style>
