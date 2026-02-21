import { Guard } from './Guard';
import { UserProvider } from './Contracts/UserProvider';
import { EventDispatcher } from './Contracts/EventDispatcher';
import { RateLimiter } from './Contracts/RateLimiter';
import { SessionGuard } from './Guards/SessionGuard';
import { TokenGuard } from './Guards/TokenGuard';
import { JwtGuard } from './Guards/JwtGuard';
import { BasicGuard } from './Guards/BasicGuard';

export class AuthManager {
    private guards: Map<string, Guard> = new Map();
    private providers: Map<string, UserProvider> = new Map();
    private eventDispatcher: EventDispatcher | null = null;
    private rateLimiter: RateLimiter | null = null;
    private config: any;

    constructor(config: any) {
        this.config = config;
    }

    public setEventDispatcher(dispatcher: EventDispatcher): void {
        this.eventDispatcher = dispatcher;
    }

    public setRateLimiter(limiter: RateLimiter): void {
        this.rateLimiter = limiter;
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

        if (config.driver === 'jwt') {
            return this.createJwtDriver(name, config);
        }

        if (config.driver === 'basic') {
            return this.createBasicDriver(name, config);
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

    private createJwtDriver(name: string, config: any): Guard {
        const provider = this.providers.get(config.provider);
        if (!provider) {
            throw new Error(`User provider [${config.provider}] is not defined.`);
        }
        return new JwtGuard(provider, this.currentRequest, config.secret || 'default_secret', config.options || {});
    }

    private createBasicDriver(name: string, config: any): Guard {
        const provider = this.providers.get(config.provider);
        if (!provider) {
            throw new Error(`User provider [${config.provider}] is not defined.`);
        }
        return new BasicGuard(provider, this.currentRequest);
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

    public async attempt(credentials: Record<string, any>, remember: boolean = false): Promise<boolean | string> {
        this.fireEvent('Auth.Attempting', { credentials, remember, guard: this.config.default });

        const throttleKey = this.getThrottleKey(credentials);

        if (throttleKey && this.rateLimiter) {
            if (await this.rateLimiter.tooManyAttempts(throttleKey, 5)) {
                this.fireEvent('Auth.Lockout', { credentials });
                throw new Error('Too many login attempts. Please try again later.');
            }
        }

        const guard = this.guard() as any;
        if (typeof guard.attempt === 'function') {
            const successOrToken = await guard.attempt(credentials, remember);

            if (successOrToken) {
                if (throttleKey && this.rateLimiter) {
                    await this.rateLimiter.clear(throttleKey);
                }
                const user = await guard.user();
                this.fireEvent('Auth.Login', { user, guard: this.config.default });
                return successOrToken; // Can return boolean true or JWT string
            }

            if (throttleKey && this.rateLimiter) {
                await this.rateLimiter.hit(throttleKey, 1); // 1 minute decay
            }

            this.fireEvent('Auth.Failed', { credentials, guard: this.config.default });
            return false;
        }

        throw new Error(`Guard [${this.config.default}] does not support login attempts.`);
    }

    public async login(user: any, remember: boolean = false): Promise<void> {
        const guard = this.guard() as any;
        if (typeof guard.login === 'function') {
            await guard.login(user, remember);
            this.fireEvent('Auth.Login', { user, guard: this.config.default });
            return;
        }
        throw new Error(`Guard [${this.config.default}] does not support login.`);
    }

    public async logout(): Promise<void> {
        const guard = this.guard() as any;
        const user = await guard.user();

        if (typeof guard.logout === 'function') {
            guard.logout();
            this.fireEvent('Auth.Logout', { user, guard: this.config.default });
            return;
        }
        throw new Error(`Guard [${this.config.default}] does not support logout.`);
    }

    private fireEvent(name: string, payload: any): void {
        if (this.eventDispatcher) {
            this.eventDispatcher.dispatch(name, payload);
        }
    }

    private getThrottleKey(credentials: Record<string, any>): string | null {
        // Typically rate limit by email and potentially IP address
        if (credentials.email) {
            const ip = this.currentRequest?.ip || '127.0.0.1';
            return `login_attempts:${credentials.email}:${ip}`;
        }
        return null;
    }
}
