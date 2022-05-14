import { BaseResponse } from 'src/common/interface/base.interface';
import { UserDto } from 'src/user/user.interface';
import { CredentialDto } from '../dto/credential.dto';

export interface RegisterResponse extends BaseResponse {
  data: UserDto;
}

export interface RefreshTokenResponse extends BaseResponse {
  data: CredentialDto;
}

export interface LoginResponse extends BaseResponse {
  data: CredentialDto;
}
