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

    // Proxy methods to the default guard
    public async check(): Promise<boolean> {
        return await this.guard().check();
    }

    public async guest(): Promise<boolean> {
        return await this.guard().guest();
    }

    public async user(): Promise<any> {
        return await this.guard().user();
    }

    public async id(): Promise<string | number | null> {
        return await this.guard().id();
    }

    public async validate(credentials: Record<string, any>): Promise<boolean> {
        return await this.guard().validate(credentials);
    }

    public setUser(user: any): void {
        this.guard().setUser(user);
    }

    public async attempt(credentials: Record<string, any>): Promise<boolean> {
        const guard = this.guard() as any;
        if (typeof guard.attempt === 'function') {
            return await guard.attempt(credentials);
        }
        throw new Error(`Guard [${this.config.default}] does not support login attempts.`);
    }

    public login(user: any): void {
        const guard = this.guard() as any;
        if (typeof guard.login === 'function') {
            guard.login(user);
            return;
        }
        throw new Error(`Guard [${this.config.default}] does not support login.`);
    }

    public logout(): void {
        const guard = this.guard() as any;
        if (typeof guard.logout === 'function') {
            guard.logout();
            return;
        }
        throw new Error(`Guard [${this.config.default}] does not support logout.`);
    }
}
