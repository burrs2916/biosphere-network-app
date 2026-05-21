export type Locale = 'en' | 'zh';

export interface LocaleInfo {
	code: Locale;
	name: string;
	nativeName: string;
}

export const SUPPORTED_LOCALES: LocaleInfo[] = [
	{ code: 'en', name: 'English', nativeName: 'English' },
	{ code: 'zh', name: 'Chinese', nativeName: '中文' }
];

export const DEFAULT_LOCALE: Locale = 'en';
