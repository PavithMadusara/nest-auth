/**
 * @author Pavith Madusara
 *
 * Created at 28-Feb-2021
 * Sunday at 1:00 PM
 */
import {Field, InputType} from '@nestjs/graphql';
import {AuthProvider} from '@arkstatic/nest-auth/auth-provider.enum';

@InputType('SignUpInput')
export class SignUpInputDTO {
    @Field({nullable: true})
    displayName?: string;

    @Field({nullable: true})
    displayPicture?: string;

    @Field()
    firstName: string;

    @Field()
    lastName: string;

    @Field({nullable: true})
    phone?: string;

    @Field({nullable: true})
    email?: string;

    @Field()
    identifier: string;

    @Field()
    verifier: string;

    @Field(() => AuthProvider)
    authProvider: AuthProvider;
}
