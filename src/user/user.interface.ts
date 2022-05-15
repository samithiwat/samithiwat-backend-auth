import { Observable } from 'rxjs';
import { BaseResponse } from 'src/common/interface/base.interface';
import { CreateUserDto } from './dto/create-user.dto';

export interface UserDto {
  firstname: string;
  lastname: string;
  displayName: string;
  imageUrl: string;
}

export interface UserService {
  create(req: CreateUserRequest): Observable<UserResponse>;
}

export interface CreateUserRequest {
  user: CreateUserDto;
}

export interface UserResponse extends BaseResponse {
  data: UserDto;
}
