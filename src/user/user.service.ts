import { Inject, Injectable } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import { CreateUserDto } from './dto/create-user.dto';
import { UserResponse, UserService as UserSrv } from './user.interface';

@Injectable()
export class UserService {
  constructor(@Inject('USER_PACKAGE') private client: ClientGrpc) {}

  private userService: UserSrv;

  onModuleInit() {
    this.userService = this.client.getService<UserSrv>('UserService');
  }

  async create(createUserDto: CreateUserDto): Promise<UserResponse> {
    return this.userService.create({ createUserDto });
  }
}
