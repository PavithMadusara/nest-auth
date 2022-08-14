/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 12:56 PM
 */
import {Args, Mutation, Query, Resolver} from '@nestjs/graphql';
import {SignUpInputDTO} from '@arkstatic/nest-auth/user/sign-up.input.dto';
import {ClientData, ClientDataModel} from '@arkstatic/nest-auth/decorators/client-data.decorator';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto-js';
import * as jwt from 'jsonwebtoken';
import * as speakeasy from 'speakeasy';
import {v4 as uuid4} from 'uuid';
import {UserEntity} from '@arkstatic/nest-auth/user/user.entity';
import {CurrentUser} from '@arkstatic/nest-auth/decorators/current-user.decorator';
import {AuthService} from '@arkstatic/nest-auth/auth.service';
import {AuthPayloadResponse} from '@arkstatic/nest-auth/auth.payload';
import {SessionEntity} from '@arkstatic/nest-auth/session/session.entity';
import {TokenPayload} from '@arkstatic/nest-auth/token.payload';
import {SessionID} from '@arkstatic/nest-auth/decorators/session-id.decorator';

@Resolver()
export class AuthResolver {

    constructor(
        private readonly authService: AuthService,
    ) {}

    @Query(() => String)
    async ping(): Promise<string> {
        return new Date().toDateString();
    }

    @Mutation(() => AuthPayloadResponse)
    async signIn(
        @Args('identifier')identifier: string,
        @Args('verifier')verifier: string,
        @ClientData(){ipAddress, userAgent}: ClientDataModel,
    ): Promise<AuthPayloadResponse> {

        const user = await UserEntity.getRepository().findOne({
            where: {identifier: identifier, deletedAt: null},
        });

        if (!user) {
            return {
                message: 'User not Available',
                isSuccessful: false,
                code: 'auth/sign-in/fail',
            };
        }

        const isValidVerifier = bcrypt.compareSync(verifier, user.verifier);

        if (!isValidVerifier) {
            return {
                message: 'Invalid Verifier',
                isSuccessful: false,
                code: 'auth/sign-in/fail',
            };
        }

        /**
         * @see signUp for details
         */
        const key = crypto.HmacSHA256(userAgent + ipAddress, verifier).toString();

        /**
         * Find existing session for the user agent
         */
        let savedSession = await SessionEntity.getRepository().findOne({where: {key: key}});
        if (!savedSession) {
            const session: Partial<SessionEntity> = {
                ipAddress,
                userAgent,
                key,
                user: user,
            };
            savedSession = await SessionEntity.getRepository().save(session);
        }

        const authPayload = await this.authService.buildAuthPayload(user, key, savedSession);

        if (user.enable2FA) {

            const verificationMethods = [];
            if (user.secret) {
                verificationMethods.push('TOTP');
            }
            if (user.phoneVerifiedAt) {
                verificationMethods.push('OTP');
            }

            /**
             * If user has enabled 2 Factor authentication, we still create the session but dont send the refresh and
             * access token on the response. instead of that we send session id as a access token. other than that we
             * send available 2FA verification methods for the user.
             */
            return {
                message: 'Two Factor Authentication Enabled',
                isSuccessful: true,
                code: 'auth/sign-in/success',
                data: {
                    ...authPayload,
                    is2FA: true,
                    accessToken: savedSession.sessionId,
                    refreshToken: null,
                    verificationMethods
                },
            };
        } else {
            return {
                isSuccessful: true,
                message: 'Sign In Successful',
                code: 'auth/sign-in/success',
                data: authPayload,
            };
        }

    }

    @Mutation(() => AuthPayloadResponse)
    async verifyTOTP(
        @Args('accessToken')accessToken: string,
        @Args('token')token: string,
    ): Promise<AuthPayloadResponse> {
        const session = await SessionEntity.getRepository().findOne(accessToken, {relations: ['user']});
        if (!session) {
            return {
                message: 'Invalid Access Token',
                isSuccessful: false,
                code: 'auth/verify-totp/fail',
            };
        }
        const user = session.user;
        const authPayload = await this.authService.buildAuthPayload(user, session.key, session);
        return {
            isSuccessful: true,
            message: 'Verification Successful',
            code: 'auth/verify-totp/success',
            data: authPayload,
        };
    }

    @Mutation(() => AuthPayloadResponse)
    async signUp(
        @Args('input')input: SignUpInputDTO,
        @ClientData(){ipAddress, userAgent}: ClientDataModel,
        @CurrentUser()currentUser: TokenPayload,
    ): Promise<AuthPayloadResponse> {

        const uuid = uuid4();

        /**
         * Verifier can be user's password or random hash based on uuid from another OAuth2 service like firebase.
         * since we are validating 3rd party OAuth service providers every time user sign in it doesnt matter if that
         * uuid got leaked. To prevent refresh token key reverse engineering we need to update 3rd party OAuth based
         * hash everytime user sign in
         */
        const verifier = await bcrypt.hashSync(input.verifier, 5);

        /**
         * Creating token sign key. we are using users verifier (password) to encrypt user agent, By using User-Agent
         * string it makes harder to use stolen tokens on another device. Since we are using user verifier (password)
         * to encrypt it we don't need to maintain a server secret for this
         */
        const key = crypto.HmacSHA256(userAgent + ipAddress, input.verifier).toString();

        /**
         * Sessions keep track of active devices. if user sign in twice in different devices we should have two
         * different session records. when user needs to refresh the access token user send the refresh token
         * we can use key stored in the corresponding session record to verify that refresh token. if we want to
         * invalidate the session we can simply delete the session. in case of a invalid session id on a refresh token
         * it can be a invalidated session or a stolen token
         */
        const session: Partial<SessionEntity> = {
            ipAddress,
            userAgent,
            key,
        };

        const userData: Partial<UserEntity> = {
            ...input,
            uuid,
            verifier,
            status: true,
            sessions: [session as SessionEntity],
        };

        userData.createdBy = currentUser?.sub || uuid;
        userData.updatedBy = currentUser?.sub || uuid;

        const user: UserEntity = userData as UserEntity;
        const savedUser = await UserEntity.getRepository().save(user);

        const authPayload = await this.authService.buildAuthPayload(savedUser, key, user.sessions[0]);

        return {
            isSuccessful: true,
            code: 'auth/sign-up/success',
            data: authPayload,
        };
    }

    @Mutation(() => AuthPayloadResponse)
    async accessTokenRefresh(
        @Args('refreshToken')refreshToken: string,
        @ClientData(){ipAddress, userAgent}: ClientDataModel,
    ): Promise<AuthPayloadResponse> {
        const decodedToken: any = jwt.decode(refreshToken);
        const sessionId = decodedToken.sid;

        const session: SessionEntity = await SessionEntity.getRepository().findOne(sessionId, {relations: ['user']});

        if (!session) {
            return {
                message: 'Token Revoked',
                isSuccessful: false,
                code: 'auth/access-token-refresh/revoked',
            };
        }

        if (ipAddress !== session.ipAddress || userAgent !== session.userAgent) {
            return {
                message: 'Unauthorized Device',
                isSuccessful: false,
                code: 'auth/access-token-refresh/fail',
            };
        }

        try {
            jwt.verify(refreshToken, session.key);

            const authPayload = await this.authService.buildAuthPayload(session.user, session.key, session);

            return {
                isSuccessful: true,
                code: 'auth/token-refresh/success',
                data: authPayload,
            };

        } catch (e) {
            return {
                message: 'Invalid Token',
                isSuccessful: false,
                code: 'auth/access-token-refresh/fail',
            };
        }

    }

    @Mutation(() => AuthPayloadResponse)
    async generateTOTPSecret(): Promise<AuthPayloadResponse> {
        return {
            isSuccessful: true,
            message: 'TOTP Code Generated',
            data: speakeasy.generateSecret().base32,
            code: 'totp/generate/success',
        };
    }

    @Mutation(() => AuthPayloadResponse)
    async enableTOTP(
        @Args('secret')secret: string,
        @Args('token')token: string,
        @CurrentUser()currentUser: TokenPayload,
    ): Promise<AuthPayloadResponse> {
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
        });
        if (verified) {
            const user = await UserEntity.getRepository().findOne(currentUser.sub);
            if (user.secret) {
                return {
                    isSuccessful: false,
                    message: 'Already Enabled',
                    code: 'totp/enable/already-enabled',
                };
            }

            user.secret = secret;
            user.enable2FA = true;
            user.save();

            return {
                isSuccessful: true,
                message: 'Enabled 2FA with TOTP Token',
                code: 'totp/enable/success',
            };

        } else {
            return {
                isSuccessful: false,
                message: 'Invalid Key',
                code: 'totp/enable/invalid-token',
            };
        }
    }

    @Mutation(() => AuthPayloadResponse)
    async disable2FA(
        @Args('verifier')verifier: string,
        @CurrentUser()currentUser: TokenPayload,
    ): Promise<AuthPayloadResponse> {
        const user = await UserEntity.getRepository().findOne(currentUser.sub);
        const isValidVerifier = bcrypt.compareSync(verifier, user.verifier);

        if (!isValidVerifier) {
            return {
                message: 'Invalid Verifier',
                isSuccessful: false,
                code: 'totp/disable/fail',
            };
        }

        user.secret = null;
        user.enable2FA = false;
        user.save();

        return {
            isSuccessful: true,
            message: 'Disabled TOTP',
            code: 'totp/disable/success',
        };

    }

    @Mutation(() => AuthPayloadResponse)
    async signOut(
        @SessionID()sessionId: string,
    ): Promise<AuthPayloadResponse> {
        await SessionEntity.getRepository()
            .createQueryBuilder().delete()
            .from(SessionEntity)
            .where('sessionId=:id', {id: sessionId})
            .execute();
        return {
            isSuccessful: true,
            code: 'auth/logout/success',
        };
    }
}
