import { HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { ServiceType } from 'src/common/enum/auth.enum';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { CreateTokenDto } from '../dto/create-token.dto';
import { CredentialDto } from '../dto/credential.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Auth } from '../entities/auth.entity';
import { LoginResponse, RegisterResponse } from '../interface/auth.interface';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';
import { TokenService } from './token.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth) private readonly authRepository: Repository<Auth>,
    private readonly tokenService: TokenService,
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto): Promise<RegisterResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.CREATED,
      errors: null,
      data: null,
    }) as RegisterResponse;

    registerDto.password = await this.tokenService.hashPassword(registerDto.password);

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

    const auth = await this.authRepository.findOne({ email: loginDto.email });
    if (!auth) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid email or password'];
      return res;
    }

    const isValid = await this.tokenService.isValidPassword(loginDto.password, auth.password);
    if (!isValid) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid email or password'];
      return res;
    }

    const accessToken = await this.jwtService.generate(auth);
    const refreshToken = await this.refreshTokenService.generate();
    const credentials = await this.tokenService.create(
      new CreateTokenDto({
        serviceType: ServiceType.APP,
        accessToken,
        refreshToken,
      }),
    );

    res.data = new CredentialDto({
      accessToken: credentials.data.accessToken,
      refreshToken: credentials.data.refreshToken,
      expiresIn: parseInt(this.configService.get<string>('jwt.tokenDuration')),
    });

    return res;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  validate(id: number) {
    return `This action removes a #${id} auth`;
  }

  refreshToken(refreshToken: string) {
    return `this action refreshes a #${refreshToken} auth`;
  }
}
