export interface UserProvider {
    retrieveById(id: string | number): Promise<any>;
    retrieveByToken?(id: string | number, token: string): Promise<any>;
    updateRememberToken?(user: any, token: string | null): Promise<void>;
    retrieveByCredentials(credentials: Record<string, any>): Promise<any>;
    validateCredentials(user: any, credentials: Record<string, any>): boolean | Promise<boolean>;
}
