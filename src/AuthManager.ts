import { Guard } from './Guard';
import { UserProvider } from './Contracts/UserProvider';
import { SessionGuard } from './Guards/SessionGuard';
import { TokenGuard } from './Guards/TokenGuard';

export class AuthManager {
    private guards: Map<string, Guard> = new Map();
    private providers: Map<string, UserProvider> = new Map();
    private config: any;

    constructor(config: any) {
        this.config = config;
    }

    public registerProvider(name: string, provider: UserProvider): void {
        this.providers.set(name, provider);
    }

    public extend(name: string, callback: (app: any) => Guard): void {
        // Implementation for custom guards
    }

    public guard(name?: string): Guard {
        name = name || this.config.default;

        // Handle undefined name from config explicitly
        if (!name) {
            throw new Error('No auth guard defined.');
        }

        if (!this.guards.has(name)) {
            this.guards.set(name, this.resolveGuard(name));
        }

        return this.guards.get(name)!;
    }

    private resolveGuard(name: string): Guard {
        const config = this.config.guards[name];

        if (!config) {
            throw new Error(`Auth guard [${name}] is not defined.`);
        }

        if (config.driver === 'session') {
            return this.createSessionDriver(name, config);
        }

        if (config.driver === 'token') {
            return this.createTokenDriver(name, config);
        }

        throw new Error(`Auth driver [${config.driver}] for guard [${name}] is not supported.`);
    }

    private currentRequest: any = {};

    public setRequest(request: any): void {
        this.currentRequest = request;
        this.guards.forEach(guard => {
            if (guard.setRequest) {
                guard.setRequest(request);
            }
        });
    }

    private createSessionDriver(name: string, config: any): SessionGuard {
        const provider = this.providers.get(config.provider);
        if (!provider) {
            throw new Error(`User provider [${config.provider}] is not defined.`);
        }
        return new SessionGuard(provider, this.currentRequest);
    }

    private createTokenDriver(name: string, config: any): Guard {
        const provider = this.providers.get(config.provider);
        if (!provider) {
            throw new Error(`User provider [${config.provider}] is not defined.`);
        }
        return new TokenGuard(provider, this.currentRequest);
    }

    public shouldUse(name: string): void {
        this.config.default = name;
    }
}
