import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { UserService } from './user.service';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        imports: [ConfigModule],
        name: 'USER_PACKAGE',
        useFactory: async (configService: ConfigService) => ({
          transport: Transport.GRPC,
          options: {
            url: `${configService.get<string>('user.host')}`,
            package: 'user',
            protoPath: join(__dirname, '../proto/user.proto'),
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [UserService],
})
export class UserModule {}
