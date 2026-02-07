import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import { AuthManager, Hasher, UserProvider } from '../src';
import { SessionGuard } from '../src/Guards/SessionGuard';

class MockPoolProvider implements UserProvider {
    private users = [
        { id: 1, email: 'test@example.com', password: '$2a$10$...' }
    ];

    async retrieveById(id: string | number): Promise<any> {
        return this.users.find(u => u.id === Number(id)) || null;
    }

    async retrieveByCredentials(credentials: Record<string, any>): Promise<any> {
        if (credentials.email === 'test@example.com') {
            return this.users[0];
        }
        return null;
    }

    validateCredentials(user: any, credentials: Record<string, any>): boolean {
        return credentials.password === 'secret';
    }
}

describe('Arika Auth', () => {
    let authManager: AuthManager;
    let config;

    beforeEach(() => {
        config = {
            default: 'web',
            guards: {
                web: { driver: 'session', provider: 'users' },
                api: { driver: 'token', provider: 'users' }
            }
        };
        authManager = new AuthManager(config);
        authManager.registerProvider('users', new MockPoolProvider());
    });

    it('resolves session guard by default', async () => {
        const guard = authManager.guard();
        assert.ok(guard);
        // We know it's a SessionGuard because of the config 'driver: session'
        const isSessionGuard = guard instanceof SessionGuard || guard.constructor.name === 'SessionGuard';
        assert.ok(isSessionGuard);
    });

    it('can attempt login via session guard', async () => {
        const guard = authManager.guard('web');
        const success = await guard.validate({ email: 'test@example.com', password: 'secret' });
        assert.strictEqual(success, true);

        const fail = await guard.validate({ email: 'test@example.com', password: 'wrong' });
        assert.strictEqual(fail, false);
    });

    it('hashes passwords securely', async () => {
        const password = 'my-secret-password';
        const hash = await Hasher.make(password);

        assert.ok(hash.length > 0);
        assert.notStrictEqual(password, hash);

        const valid = await Hasher.check(password, hash);
        assert.strictEqual(valid, true);

        const invalid = await Hasher.check('wrong', hash);
        assert.strictEqual(invalid, false);
    });
});
