import { HttpStatus } from '@nestjs/common';

export interface BaseResponse {
  statusCode: HttpStatus;
  errors: string[];
}
