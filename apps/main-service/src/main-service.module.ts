import { DatabaseModule } from '@air-bnb/database';

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import configEnv, { validate } from './config';
import { MainServiceController } from './main-service.controller';
import { MainServicesService } from './main-service.service';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { JwtAuthGuard } from './modules/auth/jwt-auth.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      validate: validate,
    }),
    DatabaseModule.forRoot({
      DB_USERNAME: configEnv.DB_USERNAME,
      DB_PASSWORD: configEnv.DB_PASSWORD,
      DB_HOST: configEnv.DB_HOST,
      DB_PORT: parseInt(configEnv.DB_PORT),
      DB_NAME: configEnv.DB_NAME,
      DB_URL: configEnv.DB_URL,
    }),
    JwtModule.register({
      global: true,
      secret: configEnv.JWT_SECRET_KEY,
      signOptions: { expiresIn: '1d' },
    }),
    AuthModule,
    UsersModule,
  ],
  controllers: [MainServiceController],
  providers: [
    MainServicesService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class MainServiceModule {}
