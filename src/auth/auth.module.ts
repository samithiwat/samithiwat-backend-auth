import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './services/auth.service';
import { JwtService } from './services/jwt.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, JwtService],
})
export class AuthModule {}
