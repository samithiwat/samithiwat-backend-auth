import { HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import * as moment from 'moment';
import { ServiceType } from 'src/common/enum/auth.enum';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { CreateTokenDto } from '../dto/create-token.dto';
import { CredentialDto } from '../dto/credential.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResponseDto } from '../dto/response.dto';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';
import {
  ChangePasswordResponse,
  LoginResponse,
  LogoutResponse,
  RefreshTokenResponse,
  RegisterResponse,
  ValidateResponse,
} from '../interface/auth.interface';
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

    registerDto.password = await this.hashPassword(registerDto.password);

    const nEmail = await this.authRepository.count({ email: registerDto.email });
    if (nEmail > 0) {
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
    await this.authRepository.save({ ...registerDto, userId: userRes.data.id });

    res.data = userRes.data;
    return res;
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.OK,
      errors: null,
      data: null,
    }) as LoginResponse;

    const auth = await this.authRepository.findOne(
      { email: loginDto.email },
      { relations: ['tokens'] },
    );

    if (!auth) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid email or password'];
      return res;
    }

    const isValid = await this.isValidPassword(loginDto.password, auth.password);
    if (!isValid) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid email or password'];
      return res;
    }

    if (!auth.isEmailVerified) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Email is not verified'];
      return res;
    }

    const accessToken = await this.jwtService.generate(auth);
    const refreshToken = await this.refreshTokenService.generate();

    const tokenDto = new CreateTokenDto({
      serviceType: ServiceType.APP,
      accessToken,
      refreshToken,
    });

    const credentials = await this.storeToken(auth, tokenDto);

    res.data = new CredentialDto({
      accessToken: credentials.accessToken,
      refreshToken: credentials.refreshToken,
      expiresIn: parseInt(this.configService.get<string>('jwt.tokenDuration')),
    });

    return res;
  }

  async logout(token: string): Promise<LogoutResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.NO_CONTENT,
      errors: null,
      data: null,
    });

    const auth = await this.validateToken(token);

    if (!auth) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid token'];
      return res;
    }

    const appToken = auth.tokens.find(token => token.serviceType === ServiceType.APP);
    await this.tokenService.remove(appToken.id);

    return res;
  }

  async changePassword(changePasswordDto: ChangePasswordDto): Promise<ChangePasswordResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.OK,
      errors: null,
      data: false,
    });

    const auth = await this.authRepository.findOne({ userId: changePasswordDto.userId });

    if (!auth) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid userId or password'];
      return res;
    }

    const isValid = await this.isValidPassword(changePasswordDto.oldPassword, auth.password);
    if (!isValid) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid userId or password'];
      return res;
    }

    const newPassword = await this.hashPassword(changePasswordDto.newPassword);
    auth.password = newPassword;

    await this.authRepository.save(auth);
    res.data = true;

    return res;
  }

  async validate(token: string): Promise<ValidateResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.OK,
      errors: null,
      data: null,
    });

    const auth = await this.validateToken(token);

    if (!auth) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid token'];
      return res;
    }

    res.data = auth.userId;

    return res;
  }

  async refreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.OK,
      errors: null,
      data: null,
    });

    let decoded: string;

    try {
      decoded = await this.tokenService.decode(refreshToken);
    } catch (err) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid refresh token'];
      return res;
    }

    const token = await this.refreshTokenService.verify(decoded);

    if (!token) {
      res.statusCode = HttpStatus.UNAUTHORIZED;
      res.errors = ['Invalid refresh token'];
      return res;
    }

    token.accessToken = await this.jwtService.generate(token.auth);
    token.refreshToken = await this.refreshTokenService.generate();

    const updatedTokenRes = await this.tokenService.update(token.id, token);
    const updatedToken = updatedTokenRes.data;

    updatedToken.refreshToken = await this.tokenService.encode(updatedToken.refreshToken);

    res.data = new CredentialDto({
      accessToken: updatedToken.accessToken,
      refreshToken: updatedToken.refreshToken,
      expiresIn: parseInt(this.configService.get<string>('jwt.tokenDuration')),
    });

    return res;
  }

  async hashPassword(password: string): Promise<string> {
    const salt: string = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  async isValidPassword(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  async validateToken(token: string): Promise<Auth> {
    const auth = await this.jwtService.validate(token);

    if (!auth) {
      return null;
    }

    if (moment(auth.tokens[0].expiresDate).isBefore(new Date())) {
      return null;
    }

    return auth;
  }

  async storeToken(auth: Auth, newToken: CreateTokenDto): Promise<Token> {
    const existedToken = auth.tokens.find(token => token.serviceType === newToken.serviceType);

    if (!existedToken) {
      newToken.auth = new Auth({ id: auth.id });
      const res = await this.tokenService.create(newToken);
      return res.data;
    }

    newToken.expiresDate = moment()
      .add(parseInt(this.configService.get<string>('jwt.tokenDuration')), 's')
      .toDate();
    const res = await this.tokenService.update(existedToken.id, newToken);
    return res.data;
  }
}
