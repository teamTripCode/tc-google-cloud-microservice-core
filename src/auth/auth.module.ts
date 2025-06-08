import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    ConfigModule,
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        baseURL: configService.get('AUTH_SERVICE_URL'),
        timeout: 5000,
        maxRedirects: 5,
      }),
      inject: [ConfigService]
    }),
  ],
  providers: [AuthService],
  exports
})
export class AuthModule { }
