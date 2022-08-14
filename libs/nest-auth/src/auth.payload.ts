/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 1:41 PM
 */
import {Field, ObjectType} from '@nestjs/graphql';
import {AuthResponse} from '@arkstatic/nest-auth/auth.response.dto';

@ObjectType('TokenPayload')
export class AuthPayload {
    @Field()
    type: string;

    @Field()
    uuid: string;

    @Field()
    identifier: string;

    @Field({nullable: true})
    accessToken?: string;

    @Field({nullable: true})
    refreshToken?: string;

    @Field({nullable: true})
    is2FA?: boolean;

    @Field(() => [String], {nullable: true})
    verificationMethods?: [string];
}

@ObjectType()
export class AuthPayloadResponse extends AuthResponse(AuthPayload) {}
