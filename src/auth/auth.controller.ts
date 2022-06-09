import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  ChangePasswordRequest,
  ChangePasswordResponse,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  RegisterRequest,
  RegisterResponse,
  ValidateRequest,
  ValidateResponse,
} from './interface/auth.interface';
import { AuthService } from './services/auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @GrpcMethod('AuthService', 'Register')
  async register(req: RegisterRequest): Promise<RegisterResponse> {
    return this.authService.register(req.register);
  }

  @GrpcMethod('AuthService', 'Login')
  async login(req: LoginRequest): Promise<LoginResponse> {
    return this.authService.login(req.login);
  }

  @GrpcMethod('AuthService', 'Logout')
  async logout(req: LogoutRequest): Promise<LogoutResponse> {
    return this.authService.logout(req.userId);
  }

  @GrpcMethod('AuthService', 'ChangePassword')
  async changePassword(req: ChangePasswordRequest): Promise<ChangePasswordResponse> {
    return this.authService.changePassword(req.changePassword);
  }

  @GrpcMethod('AuthService', 'Validate')
  async validate(req: ValidateRequest): Promise<ValidateResponse> {
    return this.authService.validate(req.token);
  }

  @GrpcMethod('AuthService', 'RedeemNewToken')
  refreshToken(req: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    return this.authService.refreshToken(req.refreshToken);
  }
}
