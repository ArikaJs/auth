import { Guard } from '../Guard';
import { UserProvider } from '../Contracts/UserProvider';
import { Hasher } from '../Hasher';

export class SessionGuard implements Guard {
    private provider: UserProvider;
    private session: any; // Ideally this should be a Session interface from @arikajs/session
    private loggedUser: any = null;

    constructor(provider: UserProvider, session: any) {
        this.provider = provider;
        this.session = session;
    }

    public async check(): Promise<boolean> {
        return !!(await this.user());
    }

    public async guest(): Promise<boolean> {
        return !(await this.check());
    }

    public async user(): Promise<any> {
        if (this.loggedUser) {
            return this.loggedUser;
        }

        const id = this.session.get ? this.session.get('auth_user_id') : null;

        if (id) {
            this.loggedUser = await this.provider.retrieveById(id);
        }

        return this.loggedUser;
    }

    public async id(): Promise<string | number | null> {
        const user = await this.user();
        return user ? user.id : null;
    }

    public async validate(credentials: Record<string, any>): Promise<boolean> {
        const user = await this.provider.retrieveByCredentials(credentials);
        if (!user) {
            return false;
        }

        return await this.provider.validateCredentials(user, credentials);
    }

    public async attempt(credentials: Record<string, any>): Promise<boolean> {
        if (await this.validate(credentials)) {
            const user = await this.provider.retrieveByCredentials(credentials);
            this.login(user);
            return true;
        }
        return false;
    }

    public login(user: any): void {
        this.loggedUser = user;
        if (this.session.put) {
            this.session.put('auth_user_id', user.id);
        }
    }

    public logout(): void {
        this.loggedUser = null;
        if (this.session.forget) {
            this.session.forget('auth_user_id');
        }
    }

    public setUser(user: any): void {
        this.loggedUser = user;
    }
}
