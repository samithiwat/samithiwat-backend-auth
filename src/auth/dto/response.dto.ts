import { HttpStatus } from '@nestjs/common';
import { UserDto } from '../../user/user.interface';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';

export class ResponseDto {
  statusCode: HttpStatus;
  errors: string[];
  data: Token | Auth | UserDto;

  constructor(partial: Partial<ResponseDto>) {
    Object.assign(this, partial);
  }
}
