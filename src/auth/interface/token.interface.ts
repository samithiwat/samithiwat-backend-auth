import { BaseResponse } from 'src/common/interface/base.interface';
import { Token } from '../entities/token.entity';

export interface TokenResponse extends BaseResponse {
  data: Token;
}
