import { BaseResponse } from 'src/common/interface/base.interface';
import { UserDto } from 'src/user/user.interface';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { CredentialDto } from '../dto/credential.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';

export interface RegisterRequest {
  register: RegisterDto;
}

export interface RegisterResponse extends BaseResponse {
  data: UserDto;
}

export interface LoginRequest {
  login: LoginDto;
}

export interface LoginResponse extends BaseResponse {
  data: CredentialDto;
}

export interface LogoutRequest {
  token: string;
}

export interface LogoutResponse extends BaseResponse {
  data: null;
}

export interface ChangePasswordRequest {
  changePassword: ChangePasswordDto;
}

export interface ChangePasswordResponse extends BaseResponse {
  data: boolean;
}

export interface ValidateRequest {
  token: string;
}

export interface ValidateResponse extends BaseResponse {
  data: number;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse extends BaseResponse {
  data: CredentialDto;
}
