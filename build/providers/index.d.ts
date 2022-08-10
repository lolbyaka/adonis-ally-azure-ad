/// <reference types="@adonisjs/application/build/adonis-typings" />
import type { ApplicationContract } from '@ioc:Adonis/Core/Application';
export default class AADProvider {
    protected app: ApplicationContract;
    constructor(app: ApplicationContract);
    boot(): Promise<void>;
}
