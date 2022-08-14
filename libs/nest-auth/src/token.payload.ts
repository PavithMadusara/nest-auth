/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 8:48 PM
 */
import {Field, ObjectType} from '@nestjs/graphql';

@ObjectType('TokenPayload')
export class TokenPayload {
    @Field()
    sid: string;

    @Field()
    audience: string;

    @Field()
    issuer: string;

    @Field()
    iat: string;

    @Field()
    exp: string;

    @Field()
    sub: string;

}
