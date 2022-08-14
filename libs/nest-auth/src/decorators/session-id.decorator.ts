/**
 * @author Pavith Madusara
 *
 * Created at 19-Jan-2021
 * Tuesday at 2:11 PM
 */
import {createParamDecorator, ExecutionContext, UnauthorizedException} from '@nestjs/common';
import {GqlExecutionContext} from '@nestjs/graphql';
import * as jwt from 'jsonwebtoken';

export const SessionID = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const ctx = GqlExecutionContext.create(context);
        const jwtToken = ctx.getContext().req.headers.authorization;
        if(!jwtToken){
            throw new UnauthorizedException('User Not Signed In');
        }
        const decodedToken: any = jwt.decode(jwtToken.replace('Bearer ', ''));
        return decodedToken.sid;
    },
);
