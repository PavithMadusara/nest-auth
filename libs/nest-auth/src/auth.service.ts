import {Injectable} from '@nestjs/common';
import {UserEntity} from '@arkstatic/nest-auth/user/user.entity';
import {SessionEntity} from '@arkstatic/nest-auth/session/session.entity';
import {SignOptions} from 'jsonwebtoken';
import {JwtService} from '@nestjs/jwt';
import {AuthPayload} from '@arkstatic/nest-auth/auth.payload';

@Injectable()
export class AuthService {

    constructor(
        private readonly jwt: JwtService,
    ) {}

    public async buildAuthPayload(user: UserEntity, key: string, session: SessionEntity): Promise<AuthPayload> {
        const accessToken = await this.generateAccessToken(user, key, session.sessionId);
        const refreshToken = await this.generateRefreshToken(user, key, session.sessionId);
        return {
            type: 'bearer',
            uuid: user.uuid,
            identifier: user.identifier,
            accessToken,
            refreshToken,
        };
    }

    async generateAccessToken(user: UserEntity, secret: string, sessionId: string, expiresIn: string = '5m'): Promise<string> {
        const opts: SignOptions = {
            expiresIn,
            subject: String(user.uuid),
        };

        return this.jwt.signAsync(
            {sid: sessionId, audience: process.env.JWT_AUDIENCE, issuer: process.env.JWT_ISSUER},
            {...opts, secret},
        );
    }

    async generateRefreshToken(user: UserEntity, secret: string, sessionId: string, expiresIn: string = '60m'): Promise<string> {
        const opts: SignOptions = {
            expiresIn,
            subject: String(user.uuid),
        };

        return this.jwt.signAsync(
            {sid: sessionId, audience: process.env.JWT_AUDIENCE, issuer: process.env.JWT_ISSUER},
            {...opts, secret},
        );
    }
}
