/**
 * @author Pavith Madusara
 *
 * Created at 14-Jan-2021
 * Thursday at 7:20 PM
 */
import {Field, ObjectType} from '@nestjs/graphql';
import {Type} from '@nestjs/common';

export function AuthResponse<T>(classRef: Type<T>): any {
    @ObjectType(`${classRef.name}Edge`)
    abstract class EdgeType {
        @Field(() => String)
        code: string;

        @Field(() => String, {nullable: true})
        message?: string;

        @Field(() => classRef, {nullable: true})
        data?: T;

        @Field(() => Boolean)
        isSuccessful: boolean;
    }

    return EdgeType;
}
