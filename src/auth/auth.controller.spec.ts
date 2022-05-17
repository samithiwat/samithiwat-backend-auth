import faker from '@faker-js/faker';
import { HttpStatus } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { UserDto } from 'src/user/user.interface';
import { AuthController } from './auth.controller';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CredentialDto } from './dto/credential.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResponseDto } from './dto/response.dto';
import { Auth } from './entities/auth.entity';
import { AuthService } from './services/auth.service';

const MockAuthService = {
  register: jest.fn(),
  login: jest.fn(),
  logout: jest.fn(),
  changePassword: jest.fn(),
  validate: jest.fn(),
  refreshToken: jest.fn(),
};

describe('AuthController', () => {
  let controller: AuthController;
  let user: UserDto;
  let auth: Auth;
  let credential: CredentialDto;

  beforeEach(async () => {
    const authModule: TestingModule = await Test.createTestingModule({
      imports: [],
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: MockAuthService,
        },
      ],
    }).compile();

    user = {
      id: 1,
      firstname: faker.name.firstName(),
      lastname: faker.name.lastName(),
      displayName: faker.internet.userName(),
      imageUrl: faker.internet.url(),
    };

    auth = new Auth({
      id: 1,
      email: faker.internet.email(),
      password: faker.internet.password(),
      isEmailVerified: true,
      userId: 1,
    });

    credential = new CredentialDto({
      accessToken: faker.internet.password(),
      refreshToken: faker.internet.password(),
      expiresIn: 3600,
    });

    controller = authModule.get<AuthController>(AuthController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: user,
      });

      const dto = new RegisterDto({});
      Object.assign(dto, auth);
      Object.assign(dto, user);

      MockAuthService.register.mockResolvedValue(want);

      const res = await controller.register({ register: dto });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.register).toBeCalledWith(dto);
    });
  });

  describe('login', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: credential,
      });

      const dto = new LoginDto({
        email: faker.internet.email(),
        password: faker.internet.password(),
      });

      MockAuthService.login.mockResolvedValue(want);

      const res = await controller.login({ login: dto });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.login).toBeCalledWith(dto);
    });
  });

  describe('logout', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NO_CONTENT,
        errors: null,
        data: null,
      });

      MockAuthService.logout.mockResolvedValue(want);

      const res = await controller.logout({ token: credential.accessToken });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.logout).toHaveBeenCalledWith(credential.accessToken);
    });
  });

  describe('validate', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: 1,
      });

      MockAuthService.validate.mockResolvedValue(want);

      const res = await controller.validate({ token: credential.accessToken });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.validate).toHaveBeenCalledWith(credential.accessToken);
    });
  });

  describe('changePassword', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: true,
      });

      const dto = new ChangePasswordDto({
        userId: 1,
        oldPassword: faker.internet.password(),
        newPassword: faker.internet.password(),
      });

      MockAuthService.changePassword.mockResolvedValue(want);

      const res = await controller.changePassword({ changePassword: dto });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.changePassword).toHaveBeenCalledWith(dto);
    });
  });

  describe('refreshToken', () => {
    it('should return response correctly', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: credential,
      });

      MockAuthService.refreshToken.mockResolvedValue(want);

      const res = await controller.refreshToken({ refreshToken: credential.refreshToken });

      expect(res).toStrictEqual(want);
      expect(MockAuthService.refreshToken).toHaveBeenCalledWith(credential.refreshToken);
    });
  });
});
