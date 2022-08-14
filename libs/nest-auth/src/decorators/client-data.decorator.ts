/**
 * @author Pavith Madusara
 *
 * Created at 21-Jan-2021
 * Thursday at 8:46 AM
 */
import {createParamDecorator, ExecutionContext} from '@nestjs/common';
import {GqlExecutionContext} from '@nestjs/graphql';

export interface ClientDataModel {
    userAgent: string;
    ipAddress: string;
}

export const ClientData = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const ctx = GqlExecutionContext.create(context);

        const ip = ctx.getContext().req.ip;
        const agent = ctx.getContext().req.headers['user-agent'];

        const clientData: ClientDataModel = {
            ipAddress: ip,
            userAgent: agent,
        };
        return clientData;
    },
);
