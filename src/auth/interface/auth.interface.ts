import { BaseResponse } from 'src/common/interface/base.interface';
import { CredentialDto } from '../dto/credential.dto';

export interface RefreshTokenResponse extends BaseResponse {
  data: CredentialDto;
}

export interface LoginResponse extends BaseResponse {
  data: CredentialDto;
}
