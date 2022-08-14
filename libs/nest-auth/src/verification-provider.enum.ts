/**
 * @author Pavith Madusara
 *
 * Created at 03-Jan-2021
 * Sunday at 6:13 PM
 */
import {registerEnumType} from '@nestjs/graphql';

export enum VerificationProvider {
    TOTP = 'TOTP',
    OTP = 'OTP',
}

registerEnumType(VerificationProvider, {
    name: 'VerificationProvider',
});
