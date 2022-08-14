import {DynamicModule, HttpModule, Module} from '@nestjs/common';
import {AuthService} from './auth.service';
import {AuthResolver} from '@arkstatic/nest-auth/auth.resolver';
import {JwtModule} from '@nestjs/jwt';

@Module({
    imports: [
        JwtModule.register({}),
        HttpModule.register({
            timeout: 5000,
            maxRedirects: 5,
        }),
    ],
    providers: [AuthService],
    exports: [AuthService],
})
export class AuthModule {
    static forRoot(): DynamicModule {
        const providers = [AuthService, AuthResolver];
        return {
            module: AuthModule,
            providers: providers,
            exports: providers,
        };
    }
}
