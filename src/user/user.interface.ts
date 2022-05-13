import { BaseResponse } from 'src/common/interface/base.interface';
import { CreateUserDto } from './dto/create-user.dto';

export interface UserDto {
  firstname: string;
  lastname: string;
  displayName: string;
  imageUrl: string;
}

export interface UserService {
  create(req: CreateUserRequest): UserResponse;
}

export interface CreateUserRequest {
  createUserDto: CreateUserDto;
}

export interface UserResponse extends BaseResponse {
  data: UserDto;
}
