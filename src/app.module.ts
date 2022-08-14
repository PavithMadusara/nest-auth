import {Module} from '@nestjs/common';
import {AppController} from './app.controller';
import {AppService} from './app.service';
import {TypeOrmModule} from '@nestjs/typeorm';
import {GraphQLModule} from '@nestjs/graphql';
import {ConfigModule} from '@nestjs/config';
import {UserEntity} from '@arkstatic/nest-auth/user/user.entity';
import {SessionEntity} from '@arkstatic/nest-auth/session/session.entity';
import {AuthModule} from '@arkstatic/nest-auth';
import {SnakeNamingStrategy} from 'typeorm-naming-strategies';

@Module({
    imports: [
        AuthModule.forRoot(),
        ConfigModule.forRoot({
            envFilePath: '.dev.env',
            ignoreEnvFile: false,
        }),
        TypeOrmModule.forRoot({
            type: 'mysql',
            autoLoadEntities: true,
            database: process.env.DB_NAME,
            dropSchema: false,
            host: process.env.DB_HOST,
            logging: true,
            password: process.env.DB_PASSWORD,
            username: process.env.DB_USERNAME,
            port: parseInt(process.env.DB_PORT),
            synchronize: true,
            namingStrategy: new SnakeNamingStrategy(),
            entities: [UserEntity, SessionEntity],
        }),
        GraphQLModule.forRoot({
            autoSchemaFile: true,
            context: ({req}) => ({req}),
        }),
    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
