import { HttpStatus } from '@nestjs/common';

export class ResponseDto {
  statusCode: HttpStatus;
  errors: string[];
  data: any;

  constructor(partial: Partial<ResponseDto>) {
    Object.assign(this, partial);
  }
}
