import { Guard } from '../Guard';
import { UserProvider } from '../Contracts/UserProvider';
import * as jwt from 'jsonwebtoken';

export class JwtGuard implements Guard {
    private provider: UserProvider;
    private request: any;
    private secret: string;
    private options: jwt.SignOptions | jwt.VerifyOptions;
    private loggedUser: any = null;

    constructor(provider: UserProvider, request: any, secret: string, options: any = {}) {
        this.provider = provider;
        this.request = request;
        this.secret = secret;
        this.options = options;
    }

    public async check(): Promise<boolean> {
        return !!(await this.user());
    }

    public async guest(): Promise<boolean> {
        return !(await this.check());
    }

    public async user(): Promise<any> {
        if (this.loggedUser) return this.loggedUser;

        const token = this.getTokenForRequest();
        if (!token) return null;

        try {
            const decoded = jwt.verify(token, this.secret, this.options as jwt.VerifyOptions) as any;
            if (decoded && decoded.sub) {
                // If the provider supports retrieving by ID, use it for stateless verification payload validation
                // In a purely stateless app, you might just return the decoded payload or a Model proxy instead
                // of querying the DB. But to ensure user is active/exists, we retrieve it:
                this.loggedUser = await this.provider.retrieveById(decoded.sub);
                return this.loggedUser;
            }
        } catch (e) {
            return null; // Invalid token
        }

        return null;
    }

    public async id(): Promise<string | number | null> {
        if (this.loggedUser) return this.loggedUser.id;

        const token = this.getTokenForRequest();
        if (!token) return null;

        try {
            const decoded = jwt.verify(token, this.secret, this.options as jwt.VerifyOptions) as any;
            return decoded ? decoded.sub : null;
        } catch (e) {
            return null;
        }
    }

    public async validate(credentials: Record<string, any>): Promise<boolean> {
        const user = await this.provider.retrieveByCredentials(credentials);
        if (!user) return false;

        return await this.provider.validateCredentials(user, credentials);
    }

    /**
     * Authenticate a user and return a JWT token
     */
    public async attempt(credentials: Record<string, any>): Promise<string | false> {
        const user = await this.provider.retrieveByCredentials(credentials);
        if (user && await this.provider.validateCredentials(user, credentials)) {
            this.login(user);
            return this.issueToken(user);
        }
        return false;
    }

    public issueToken(user: any, additionalPayload: object = {}): string {
        const payload = { sub: user.id, ...additionalPayload };
        return jwt.sign(payload, this.secret, this.options as jwt.SignOptions);
    }

    public login(user: any): void {
        this.setUser(user);
    }

    public logout(): void {
        this.loggedUser = null;
    }

    public setUser(user: any): void {
        this.loggedUser = user;
        if (this.request) {
            this.request.user = user;
        }
    }

    public setRequest(request: any): void {
        this.request = request;
    }

    protected getTokenForRequest(): string | null {
        if (this.request?.headers?.['authorization']) {
            const authHeader = this.request.headers['authorization'];
            if (authHeader.startsWith('Bearer ')) {
                return authHeader.substring(7);
            }
        }
        return null;
    }
}
