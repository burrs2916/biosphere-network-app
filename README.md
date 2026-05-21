# Biosphere Network App

A powerful network security tools platform built with Tauri, SvelteKit, and Rust.

## Features

- **Network Tools**: Comprehensive suite of network security tools
- **Modern UI**: Built with Svelte 5 and TypeScript
- **High Performance**: Rust backend for optimal performance
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Available Tools

### Information Gathering
- **Host to IP**: Convert hostname to IP address
- More tools coming soon...

## Development

### Prerequisites

- Node.js 18+
- Rust 1.70+
- pnpm

### Setup

```bash
# Install dependencies
pnpm install

# Run in development mode
pnpm tauri dev

# Build for production
pnpm tauri build
```

## Architecture

```
biosphere-network-app/
├── src/                    # Svelte frontend
├── src-tauri/              # Rust backend
└── biosphere-network/      # Network tools library
```

## License

MIT OR Apache-2.0
