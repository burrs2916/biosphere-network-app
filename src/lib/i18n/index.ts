import { writable, derived, get } from 'svelte/store';
import en from './locales/en.json';
import zh from './locales/zh.json';
import { DEFAULT_LOCALE, SUPPORTED_LOCALES, type Locale } from './types';

type TranslationData = typeof en;

const translations: Record<Locale, TranslationData> = { en, zh };

const STORAGE_KEY = 'biosphere-locale';

function loadSavedLocale(): Locale {
	if (typeof window === 'undefined') return DEFAULT_LOCALE;
	try {
		const saved = localStorage.getItem(STORAGE_KEY);
		if (saved && saved in translations) return saved as Locale;
	} catch {
		// ignore
	}
	return DEFAULT_LOCALE;
}

export const locale = writable<Locale>(DEFAULT_LOCALE);

function resolveNestedValue(obj: any, path: string): string | undefined {
	const keys = path.split('.');
	let current: any = obj;
	for (const key of keys) {
		if (current == null || typeof current !== 'object') return undefined;
		current = current[key];
	}
	return typeof current === 'string' ? current : undefined;
}

function translate(currentLocale: Locale, key: string, params?: Record<string, string | number>): string {
	const value = resolveNestedValue(translations[currentLocale], key) ?? resolveNestedValue(translations[DEFAULT_LOCALE], key) ?? key;
	if (params) {
		return Object.entries(params).reduce(
			(str, [k, v]) => str.replace(`{${k}}`, String(v)),
			value
		);
	}
	return value;
}

export function t(key: string, params?: Record<string, string | number>): string {
	return translate(get(locale), key, params);
}

export const tr = derived(locale, ($locale) => {
	return (key: string, params?: Record<string, string | number>): string => {
		return translate($locale, key, params);
	};
});

export function setLocale(newLocale: Locale): void {
	locale.set(newLocale);
	if (typeof window !== 'undefined') {
		try {
			localStorage.setItem(STORAGE_KEY, newLocale);
		} catch {
			// ignore
		}
	}
}

export function getLocale(): Locale {
	return get(locale);
}

export function initLocale(): void {
	const saved = loadSavedLocale();
	locale.set(saved);
}

export { SUPPORTED_LOCALES, DEFAULT_LOCALE };
export type { Locale };
export type { LocaleInfo } from './types';
