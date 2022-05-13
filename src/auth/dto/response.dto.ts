import { HttpStatus } from '@nestjs/common';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';
import { UserDto } from '../interface/user.interface';

export class ResponseDto {
  statusCode: HttpStatus;
  errors: string[];
  data: Token | Auth | UserDto;

  constructor(partial: Partial<ResponseDto>) {
    Object.assign(this, partial);
  }
}
