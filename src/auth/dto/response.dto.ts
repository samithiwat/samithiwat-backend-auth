import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';

export class ResponseDto {
  statusCode: number;
  errors: string[];
  data: Token | Auth;

  constructor(partial: Partial<ResponseDto>) {
    Object.assign(this, partial);
  }
}
