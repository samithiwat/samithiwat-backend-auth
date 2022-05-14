import { HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Auth } from '../entities/auth.entity';
import { LoginResponse, RegisterResponse } from '../interface/auth.interface';
import { TokenService } from './token.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth) private readonly authRepository: Repository<Auth>,
    private readonly tokenService: TokenService,
    private readonly userService: UserService,
  ) {}

  async register(registerDto: RegisterDto): Promise<RegisterResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.CREATED,
      errors: null,
      data: null,
    }) as RegisterResponse;

    try {
      await this.authRepository.save(registerDto);
    } catch (err) {
      res.statusCode = HttpStatus.UNPROCESSABLE_ENTITY;
      res.errors = ['Email is already existed'];
      return res;
    }

    const userDto = new CreateUserDto({
      firstname: registerDto.firstname,
      lastname: registerDto.lastname,
      displayName: registerDto.displayName,
      imageUrl: registerDto.imageUrl,
    });

    const userRes = await this.userService.create(userDto);

    res.data = userRes.data;
    return res;
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.OK,
      errors: null,
      data: null,
    }) as LoginResponse;

    return res;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  validate(id: number) {
    return `This action removes a #${id} auth`;
  }

  refreshToken(refreshToken) {
    return `this action refreshes a #${refreshToken} auth`;
  }
}
