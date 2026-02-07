export interface UserProvider {
    retrieveById(id: string | number): Promise<any>;
    retrieveByCredentials(credentials: Record<string, any>): Promise<any>;
    validateCredentials(user: any, credentials: Record<string, any>): boolean | Promise<boolean>;
}
