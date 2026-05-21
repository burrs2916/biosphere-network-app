type EventMap = {
    'log:info': { message: string; data?: unknown };
    'log:error': { message: string; error?: unknown };
};

type EventKey = keyof EventMap;

class EventBus {
    private listeners: Map<EventKey, Set<(data: EventMap[EventKey]) => void>> = new Map();

    on<K extends EventKey>(event: K, callback: (data: EventMap[K]) => void): () => void {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event)!.add(callback as (data: EventMap[EventKey]) => void);

        return () => this.off(event, callback);
    }

    off<K extends EventKey>(event: K, callback: (data: EventMap[K]) => void): void {
        this.listeners.get(event)?.delete(callback as (data: EventMap[EventKey]) => void);
    }

    emit<K extends EventKey>(event: K, data: EventMap[K]): void {
        console.log(`[EventBus] ${event}`, data);
        this.listeners.get(event)?.forEach(cb => cb(data));
    }
}

export const eventBus = new EventBus();
