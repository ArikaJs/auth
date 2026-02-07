import { AuthManager } from '../AuthManager';

export class Authenticate {
    constructor(private auth: AuthManager) { }

    public async handle(request: any, next: () => Promise<any>, ...guards: string[]): Promise<any> {
        // 1. Bind the current request to the AuthManager/Guards
        this.auth.setRequest(request);

        // 2. Determine guards to check
        if (guards.length === 0) {
            guards = [undefined as unknown as string]; // Use default guard
        }

        // 3. Check each guard
        for (const guard of guards) {
            if (await this.auth.guard(guard).check()) {
                this.auth.shouldUse(guard);
                return next();
            }
        }

        // 4. Fail if no guard authenticated
        throw new Error('Unauthenticated.');
    }
}
