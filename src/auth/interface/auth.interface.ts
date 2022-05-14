import { BaseResponse } from 'src/common/interface/base.interface';
import { UserDto } from 'src/user/user.interface';
import { CredentialDto } from '../dto/credential.dto';

export interface RegisterResponse extends BaseResponse {
  data: UserDto;
}

export interface LoginResponse extends BaseResponse {
  data: CredentialDto;
}

export interface ChangePasswordResponse extends BaseResponse {
  data: boolean;
}

export interface ValidateResponse extends BaseResponse {
  data: number;
}

export interface RefreshTokenResponse extends BaseResponse {
  data: CredentialDto;
}
