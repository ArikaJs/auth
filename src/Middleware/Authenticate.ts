import { AuthManager } from '../AuthManager';

export class Authenticate {
    protected guards: string[] = [];

    constructor(private auth: AuthManager) { }

    /**
     * Set the guards that should be checked.
     */
    public using(...guards: string[]): this {
        this.guards = guards;
        return this;
    }

    /**
     * Handle the incoming request.
     */
    public async handle(request: any, next: (request: any) => Promise<any> | any): Promise<any> {
        // 1. Bind the current request to the AuthManager/Guards
        this.auth.setRequest(request);

        // 2. Determine guards to check
        const guardsToCheck = this.guards.length === 0
            ? [undefined as unknown as string]
            : this.guards;

        // 3. Check each guard
        for (const guard of guardsToCheck) {
            if (await this.auth.guard(guard).check()) {
                this.auth.shouldUse(guard);
                return next(request);
            }
        }

        // 4. Fail if no guard authenticated
        throw new Error('Unauthenticated.');
    }
}
